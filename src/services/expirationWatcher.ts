import { OrderRepository } from '../database/orderRepository.ts';
import type { IWhatsAppGateway } from '../types/domain.ts';
import { formatBrl } from '../utils/cpfCnpjValidator.ts';
import type { ConversationEngine } from './conversationEngine.ts';

export class ExpirationWatcher {
  private timer: NodeJS.Timeout | null = null;
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

  public start(intervalMs = 10_000): void {
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
    const pending = this.repository.listPendingOrders();
    let expiredCount = 0;
    let warnedCount = 0;
    const provider = this.engine?.getCryptoProvider();

    for (const order of pending) {
      // 1. Verifica automaticamente na API se o Pix já foi pago (dispensa configurar Webhook!)
      if (provider && provider.name === order.provider && provider.checkChargeStatus) {
        const remote = await provider.checkChargeStatus(order.providerChargeId);
        if (remote && remote.status === 'SETTLED_CRYPTO' && this.engine) {
          await this.engine.handleSettlementWebhook({
            provider: order.provider,
            providerChargeId: order.providerChargeId,
            externalId: order.externalId,
            newStatus: 'SETTLED_CRYPTO',
            txHash: remote.txHash,
            cryptoAmount: remote.cryptoAmount,
            rawEventName: 'AUTO_POLL_CONFIRMED',
          });
          continue;
        }
      }

      // 2. Verifica tempo de expiração da chave Pix
      const expiresMs = new Date(order.expiresAt).getTime();
      const diffMs = expiresMs - now.getTime();

      if (diffMs <= 0) {
        const updated = this.repository.updateOrderStatus(order.id, 'EXPIRED');
        if (updated) {
          expiredCount++;
          await this.whatsapp.sendText(
            order.customerPhone,
            `⏰ *Atenção: A chave Pix de ${formatBrl(order.amountBrl)} expirou.*\n\n` +
              `Não realize o pagamento no código vencido. Se quiser pagar agora, basta responder com o valor (*${order.amountBrl.toFixed(2).replace('.', ',')}*) que gero uma chave nova em segundos!`
          );
        }
      } else if (!order.warningSent && diffMs <= this.warningBeforeMinutes * 60_000) {
        this.repository.markWarningSent(order.id);
        warnedCount++;
        const minsLeft = Math.max(1, Math.ceil(diffMs / 60_000));
        await this.whatsapp.sendText(
          order.customerPhone,
          `⏳ *Lembrete:* Sua chave Pix de *${formatBrl(order.amountBrl)}* vence em *${minsLeft} min*.`
        );
      }
    }

    return { expiredCount, warnedCount };
  }
}
