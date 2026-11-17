import { OrderRepository } from '../database/orderRepository.ts';
import type { IWhatsAppGateway, PixCryptoOrder } from '../types/domain.ts';
import { formatBrl } from '../utils/cpfCnpjValidator.ts';
import type { ConversationEngine } from './conversationEngine.ts';

const MAX_API_POLLS_PER_SWEEP = 2;
const MAX_TOTAL_API_CALLS_PER_SWEEP = 5; // Teto global estrito (máx 20 req/min < 30 req/min da DePix App)
const PENDING_POLL_COOLDOWN_MS = 14_000;
const CONFIRMED_POLL_COOLDOWN_MS = 120_000;

export class ExpirationWatcher {
  private timer: NodeJS.Timeout | null = null;
  private isSweeping = false;
  private readonly lastPolledAt = new Map<string, number>();
  private readonly repository: OrderRepository;
  private readonly whatsapp: IWhatsAppGateway;
  private readonly warningBeforeMinutes: number;
  private readonly engine?: ConversationEngine;

  constructor(
    repository: OrderRepository,
    whatsapp: IWhatsAppGateway,
    warningBeforeMinutes: number,
    engine?: ConversationEngine
  ) {
    this.repository = repository;
    this.whatsapp = whatsapp;
    this.warningBeforeMinutes = warningBeforeMinutes;
    this.engine = engine;
  }

  public start(intervalMs = 15_000): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.sweepPendingOrders().catch((err) => {
        console.error('[ExpirationWatcher] Erro na varredura periódica:', err);
      });
    }, intervalMs);
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  public async sweepPendingOrders(now = new Date()): Promise<{
    expiredCount: number;
    warnedCount: number;
  }> {
    if (this.isSweeping) {
      return { expiredCount: 0, warnedCount: 0 };
    }

    this.isSweeping = true;
    try {
      const sweepStartedMs = Date.now();
      const activeOrders = this.repository.listActiveUnsettledOrders();
      const nowMs = now.getTime();
      let expiredCount = 0;
      let warnedCount = 0;
      let apiCallsUsed = 0;
      const provider = this.engine?.getCryptoProvider();
      const verifiedUnpaidIds = new Set<string>();

      const activeIds = new Set(activeOrders.map((o) => o.id));
      for (const cachedId of this.lastPolledAt.keys()) {
        if (!activeIds.has(cachedId)) {
          this.lastPolledAt.delete(cachedId);
        }
      }

      const eligibleForPoll: PixCryptoOrder[] = [];
      if (provider && provider.name !== 'mock') {
        for (const order of activeOrders) {
          if (order.provider !== provider.name) continue;
          const lastMs = this.lastPolledAt.get(order.id) ?? 0;
          const cooldown =
            order.status === 'PENDING' ? PENDING_POLL_COOLDOWN_MS : CONFIRMED_POLL_COOLDOWN_MS;
          if (nowMs - lastMs >= cooldown) {
            eligibleForPoll.push(order);
          }
        }
        eligibleForPoll.sort(
          (a, b) => (this.lastPolledAt.get(a.id) ?? 0) - (this.lastPolledAt.get(b.id) ?? 0)
        );
      }

      const pollIdsThisCycle = new Set(
        eligibleForPoll.slice(0, MAX_API_POLLS_PER_SWEEP).map((o) => o.id)
      );

      for (const order of activeOrders) {
        // 1. Consulta periódica respeitando orçamento global por ciclo
        if (
          provider &&
          pollIdsThisCycle.has(order.id) &&
          apiCallsUsed < MAX_TOTAL_API_CALLS_PER_SWEEP
        ) {
          apiCallsUsed++;
          this.lastPolledAt.set(order.id, nowMs);
          const remote = await provider.checkChargeStatus(order.providerChargeId);
          if (
            remote?.status === 'SETTLED_CRYPTO' &&
            order.providerChargeId.startsWith('prd_')
          ) {
            apiCallsUsed++;
          }

          if (remote) {
            if (
              this.engine &&
              (remote.status === 'SETTLED_CRYPTO' ||
                (remote.status === 'PIX_CONFIRMED' && order.status === 'PENDING') ||
                remote.status === 'FAILED')
            ) {
              await this.engine.handleSettlementWebhook({
                provider: order.provider,
                providerChargeId: order.providerChargeId,
                externalId: order.externalId,
                newStatus: remote.status,
                txHash: remote.txHash,
                cryptoAmount: remote.cryptoAmount,
                rawEventName: 'AUTO_POLL_STATUS',
              });
              continue;
            }

            if (remote.status === 'PENDING') {
              if (remote.activePendingExpiresAt) {
                this.repository.extendOrderExpiration(order.id, remote.activePendingExpiresAt);
                if (remote.activePendingExpiresAt > order.expiresAt) {
                  order.expiresAt = remote.activePendingExpiresAt;
                }
                if (new Date(remote.activePendingExpiresAt).getTime() <= nowMs) {
                  verifiedUnpaidIds.add(order.id);
                }
              } else {
                verifiedUnpaidIds.add(order.id);
              }
            } else if (remote.status === 'EXPIRED') {
              verifiedUnpaidIds.add(order.id);
            }
          }
        }

        // 2. Pedidos já pagos (`PIX_CONFIRMED`) no Cofre nunca expiram
        if (order.status !== 'PENDING') {
          continue;
        }

        // 3. Verificação de expiração de `PENDING`
        const expiresMs = new Date(order.expiresAt).getTime();
        const diffMs = expiresMs - nowMs;

        if (diffMs <= 0) {
          const isRemoteProvider =
            Boolean(provider) &&
            order.provider === provider?.name &&
            order.provider !== 'mock';
          const needsRemoteDeactivate =
            isRemoteProvider && Boolean(provider?.expireCharge) && !order.remoteDeactivated;

          if (isRemoteProvider && provider) {
            if (!verifiedUnpaidIds.has(order.id)) {
              // Se já consultamos neste ciclo e veio `null` (429/503/timeout), nunca expira às cegas!
              if (pollIdsThisCycle.has(order.id)) {
                continue;
              }

              const callsNeeded = needsRemoteDeactivate ? 2 : 1;
              if (apiCallsUsed + callsNeeded > MAX_TOTAL_API_CALLS_PER_SWEEP) {
                // Adia 15s para o próximo ciclo garantindo poll + deactivate dentro do orçamento!
                continue;
              }

              apiCallsUsed++;
              this.lastPolledAt.set(order.id, nowMs);
              const lastChance = await provider.checkChargeStatus(order.providerChargeId);
              if (
                lastChance?.status === 'SETTLED_CRYPTO' &&
                order.providerChargeId.startsWith('prd_')
              ) {
                apiCallsUsed++;
              }

              // Em erro transitório de rede / 429 / 503 (`null`), preserva `PENDING` para o próximo ciclo!
              if (!lastChance) {
                continue;
              }

              if (
                this.engine &&
                (lastChance.status === 'SETTLED_CRYPTO' ||
                  lastChance.status === 'PIX_CONFIRMED' ||
                  lastChance.status === 'FAILED')
              ) {
                await this.engine.handleSettlementWebhook({
                  provider: order.provider,
                  providerChargeId: order.providerChargeId,
                  externalId: order.externalId,
                  newStatus: lastChance.status,
                  txHash: lastChance.txHash,
                  cryptoAmount: lastChance.cryptoAmount,
                  rawEventName: 'AUTO_POLL_BEFORE_EXPIRE',
                });
                continue;
              }

              if (
                lastChance.status === 'PENDING' &&
                lastChance.activePendingExpiresAt &&
                new Date(lastChance.activePendingExpiresAt).getTime() > nowMs
              ) {
                this.repository.extendOrderExpiration(order.id, lastChance.activePendingExpiresAt);
                continue;
              }
            } else if (
              needsRemoteDeactivate &&
              apiCallsUsed >= MAX_TOTAL_API_CALLS_PER_SWEEP
            ) {
              continue;
            }
          }

          const effectiveNowIso = new Date(
            nowMs + Math.max(0, Date.now() - sweepStartedMs)
          ).toISOString();
          const updated = this.repository.updateOrderStatus(order.id, 'EXPIRED', effectiveNowIso);
          if (updated) {
            expiredCount++;
            if (needsRemoteDeactivate && provider?.expireCharge) {
              if (apiCallsUsed < MAX_TOTAL_API_CALLS_PER_SWEEP) {
                apiCallsUsed++;
                const ok = await provider.expireCharge(order.providerChargeId);
                if (ok) {
                  this.repository.markRemoteDeactivated(order.id);
                }
              }
            }

            // Se o cliente já gerou outra cobrança mais recente (ativa ou já paga), não sobrescreve sessão nem manda falso aviso de expiração!
            const otherActive = this.repository.findActivePendingOrderByPhone(
              order.customerPhone,
              effectiveNowIso
            );
            const mostRecent = this.repository.findMostRecentOrderByPhone(order.customerPhone);
            const hasNewerOrder =
              Boolean(otherActive) ||
              Boolean(
                mostRecent &&
                  mostRecent.id !== order.id &&
                  mostRecent.createdAt >= order.createdAt
              );

            if (!hasNewerOrder) {
              const sess = this.repository.getSession(order.customerPhone);
              const hadDecisionMenu = sess.stage === 'AWAITING_ACTIVE_ORDER_DECISION';
              this.repository.saveSession({
                phone: order.customerPhone,
                customerJid: order.customerJid ?? sess.customerJid,
                stage: 'AWAITING_AMOUNT',
                draftAmountBrl: hadDecisionMenu ? -1 : undefined,
                pendingNewAmountBrl: hadDecisionMenu ? sess.pendingNewAmountBrl : undefined,
                updatedAt: effectiveNowIso,
              });

              try {
                await this.whatsapp.sendText(
                  order.customerPhone,
                  `⏰ *Atenção: A cobrança Pix de ${formatBrl(order.amountBrl)} expirou.*\n\n` +
                    `Não realize o pagamento em link/código vencido. Se quiser pagar agora, basta enviar o valor (*${order.amountBrl.toFixed(2).replace('.', ',')}*) que gero uma nova na hora!`,
                  order.customerJid
                );
              } catch (err) {
                console.error('[ExpirationWatcher] Erro ao notificar expiração:', err);
              }
            }
          }
        } else if (!order.warningSent && diffMs <= this.warningBeforeMinutes * 60_000) {
          if (this.repository.markWarningSent(order.id)) {
            warnedCount++;
            const minsLeft = Math.max(1, Math.ceil(diffMs / 60_000));
            try {
              await this.whatsapp.sendText(
                order.customerPhone,
                `⏳ *Lembrete:* Sua cobrança Pix de *${formatBrl(order.amountBrl)}* vence em *${minsLeft} min*.`,
                order.customerJid
              );
            } catch (err) {
              console.error('[ExpirationWatcher] Erro ao notificar aviso prévio:', err);
            }
          }
        }
      }

      // 4. Fila persistente de retentativa de `/deactivate` para cobranças EXPIRED / CANCELLED / FAILED
      if (provider && provider.expireCharge && apiCallsUsed < MAX_TOTAL_API_CALLS_PER_SWEEP) {
        const remainingBudget = MAX_TOTAL_API_CALLS_PER_SWEEP - apiCallsUsed;
        const pendingDeactivations = this.repository.listPendingRemoteDeactivations(
          provider.name,
          remainingBudget
        );
        for (const staleOrder of pendingDeactivations) {
          if (apiCallsUsed >= MAX_TOTAL_API_CALLS_PER_SWEEP) break;
          apiCallsUsed++;
          const ok = await provider.expireCharge(staleOrder.providerChargeId);
          if (ok) {
            this.repository.markRemoteDeactivated(staleOrder.id);
          }
        }
      }

      return { expiredCount, warnedCount };
    } finally {
      this.isSweeping = false;
    }
  }
}
