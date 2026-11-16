import { OrderRepository } from '../database/orderRepository.ts';
import type { IWhatsAppGateway, PixCryptoOrder } from '../types/domain.ts';
import { formatBrl } from '../utils/cpfCnpjValidator.ts';
import type { ConversationEngine } from './conversationEngine.ts';

const MAX_API_POLLS_PER_SWEEP = 3;
const MAX_TOTAL_API_CALLS_PER_SWEEP = 5; // Teto global estrito (máx 20 req/min < 30 req/min da DePix)
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
      const activeOrders = this.repository.listActiveUnsettledOrders();
      const nowMs = now.getTime();
      let expiredCount = 0;
      let warnedCount = 0;
      let apiCallsUsed = 0;
      const provider = this.engine?.getCryptoProvider();

      const activeIds = new Set(activeOrders.map((o) => o.id));
      for (const cachedId of this.lastPolledAt.keys()) {
        if (!activeIds.has(cachedId)) {
          this.lastPolledAt.delete(cachedId);
        }
      }

      const eligibleForPoll: PixCryptoOrder[] = [];
      if (provider) {
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
        // 1. Consulta ativa respeitando orçamento global por ciclo
        if (
          provider &&
          pollIdsThisCycle.has(order.id) &&
          apiCallsUsed < MAX_TOTAL_API_CALLS_PER_SWEEP
        ) {
          apiCallsUsed++;
          this.lastPolledAt.set(order.id, nowMs);
          const remote = await provider.checkChargeStatus(order.providerChargeId);
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

            if (remote.status === 'PENDING' && remote.activePendingExpiresAt) {
              this.repository.extendOrderExpiration(order.id, remote.activePendingExpiresAt);
              if (remote.activePendingExpiresAt > order.expiresAt) {
                order.expiresAt = remote.activePendingExpiresAt;
              }
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
          // Se o provedor suporta consulta remota e não foi checado neste ciclo, exige 1 checagem final dentro do orçamento!
          if (
            provider &&
            order.provider === provider.name &&
            order.provider !== 'mock' &&
            !pollIdsThisCycle.has(order.id)
          ) {
            if (apiCallsUsed >= MAX_TOTAL_API_CALLS_PER_SWEEP) {
              // Adia 15s para o próximo ciclo em vez de expirar às cegas sem checar na API!
              continue;
            }
            apiCallsUsed++;
            this.lastPolledAt.set(order.id, nowMs);
            const lastChance = await provider.checkChargeStatus(order.providerChargeId);
            if (lastChance) {
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
            }
          }

          const updated = this.repository.updateOrderStatus(order.id, 'EXPIRED');
          if (updated) {
            expiredCount++;
            if (
              provider &&
              provider.name === order.provider &&
              provider.expireCharge &&
              apiCallsUsed < MAX_TOTAL_API_CALLS_PER_SWEEP
            ) {
              apiCallsUsed++;
              await provider.expireCharge(order.providerChargeId);
            }

            // Coloca sessão em `AWAITING_AMOUNT` para que o cliente possa responder o valor direto no modo `keyword_only`!
            const otherActive = this.repository.findActivePendingOrderByPhone(
              order.customerPhone,
              now.toISOString()
            );
            if (!otherActive) {
              const sess = this.repository.getSession(order.customerPhone);
              this.repository.saveSession({
                phone: order.customerPhone,
                customerJid: order.customerJid ?? sess.customerJid,
                stage: 'AWAITING_AMOUNT',
                updatedAt: now.toISOString(),
              });
            }

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
        } else if (!order.warningSent && diffMs <= this.warningBeforeMinutes * 60_000) {
          this.repository.markWarningSent(order.id);
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

      return { expiredCount, warnedCount };
    } finally {
      this.isSweeping = false;
    }
  }
}
