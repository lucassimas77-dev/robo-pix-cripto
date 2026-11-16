import { OrderRepository } from '../database/orderRepository.ts';
import type { IWhatsAppGateway } from '../types/domain.ts';
import { formatBrl } from '../utils/cpfCnpjValidator.ts';
import type { ConversationEngine } from './conversationEngine.ts';

export class ExpirationWatcher {
  private timer: NodeJS.Timeout | null = null;
  private isSweeping = false;
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
      void this.sweepPendingOrders();
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
      let expiredCount = 0;
      let warnedCount = 0;
      const provider = this.engine?.getCryptoProvider();

      for (const order of activeOrders) {
        // 1. Consulta ativa na API (confirma pagamentos e estende validade se houver QR recém-gerado no link)
        if (provider && provider.name === order.provider) {
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
              order.expiresAt =
                remote.activePendingExpiresAt > order.expiresAt
                  ? remote.activePendingExpiresAt
                  : order.expiresAt;
            }
          }
        }

        // 2. Pedidos já pagos (`PIX_CONFIRMED`) aguardando liquidação on-chain jamais expiram!
        if (order.status !== 'PENDING') {
          continue;
        }

        // 3. Verifica prazo de expiração
        const expiresMs = new Date(order.expiresAt).getTime();
        const diffMs = expiresMs - now.getTime();

        if (diffMs <= 0) {
          const updated = this.repository.updateOrderStatus(order.id, 'EXPIRED');
          if (updated) {
            expiredCount++;
            if (provider && provider.name === order.provider && provider.expireCharge) {
              void provider.expireCharge(order.providerChargeId);
            }
            await this.whatsapp.sendText(
              order.customerPhone,
              `⏰ *Atenção: A cobrança Pix de ${formatBrl(order.amountBrl)} expirou.*\n\n` +
                `Não realize o pagamento em link/código vencido. Se quiser pagar agora, basta enviar o valor (*${order.amountBrl.toFixed(2).replace('.', ',')}*) que gero uma nova na hora!`,
              order.customerJid
            );
          }
        } else if (!order.warningSent && diffMs <= this.warningBeforeMinutes * 60_000) {
          this.repository.markWarningSent(order.id);
          warnedCount++;
          const minsLeft = Math.max(1, Math.ceil(diffMs / 60_000));
          await this.whatsapp.sendText(
            order.customerPhone,
            `⏳ *Lembrete:* Sua cobrança Pix de *${formatBrl(order.amountBrl)}* vence em *${minsLeft} min*.`,
            order.customerJid
          );
        }
      }

      return { expiredCount, warnedCount };
    } finally {
      this.isSweeping = false;
    }
  }
}
