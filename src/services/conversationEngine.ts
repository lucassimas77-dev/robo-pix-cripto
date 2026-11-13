import crypto from 'node:crypto';
import type { AppConfig } from '../config/env.ts';
import { OrderRepository } from '../database/orderRepository.ts';
import type {
  IPixCryptoProvider,
  IWhatsAppGateway,
  PixCryptoOrder,
  WebhookSettlementEvent,
} from '../types/domain.ts';
import {
  formatBrl,
  maskDocument,
  onlyDigits,
  parseBrlAmountFromText,
  validateAndCleanDocument,
} from '../utils/cpfCnpjValidator.ts';

/**
 * Motor Conversacional com Foco em Privacidade & Zero Identificação:
 * Por padrão (`REQUIRE_PAYER_DOCUMENT=false`), o pagador no WhatsApp informa APENAS o valor
 * (ou já manda "Me gera um Pix de 150") e recebe na hora a chave Pix dinâmica!
 */
export class ConversationEngine {
  private config: AppConfig;
  private readonly repository: OrderRepository;
  private cryptoProvider: IPixCryptoProvider;
  private readonly whatsapp: IWhatsAppGateway;

  constructor(
    config: AppConfig,
    repository: OrderRepository,
    cryptoProvider: IPixCryptoProvider,
    whatsapp: IWhatsAppGateway
  ) {
    this.config = config;
    this.repository = repository;
    this.cryptoProvider = cryptoProvider;
    this.whatsapp = whatsapp;
  }

  public getCryptoProvider(): IPixCryptoProvider {
    return this.cryptoProvider;
  }

  public updateRuntimeAccount(newConfig: AppConfig, newProvider: IPixCryptoProvider): void {
    this.config = newConfig;
    this.cryptoProvider = newProvider;
  }

  public async handleIncomingMessage(params: {
    phone: string;
    text: string;
    customerName?: string;
  }): Promise<void> {
    const phone = onlyDigits(params.phone);
    const text = params.text.trim();
    if (!phone || !text) return;

    this.repository.logMessage({
      phone,
      direction: 'INBOUND',
      type: 'TEXT',
      body: text,
      createdAt: new Date().toISOString(),
    });

    const lower = text.toLowerCase();
    const session = this.repository.getSession(phone);

    // Comando global de cancelamento/reinício
    if (['cancelar', 'sair', 'reiniciar', 'reset'].includes(lower)) {
      const activeOrder = this.repository.findActivePendingOrderByPhone(phone);
      if (activeOrder) {
        this.repository.updateOrderStatus(activeOrder.id, 'CANCELLED');
      }
      this.repository.saveSession({
        phone,
        stage: 'IDLE',
        updatedAt: new Date().toISOString(),
      });
      await this.whatsapp.sendText(
        phone,
        '✅ Atendimento reiniciado.\n\nPara gerar uma nova chave Pix imediata, basta enviar o *valor em Reais* (ex: *150,00*).'
      );
      return;
    }

    // Consulta de status
    if (['status', 'comprovante', 'meu pix'].includes(lower)) {
      const active = this.repository.findActivePendingOrderByPhone(phone);
      if (active) {
        const remainingMin = Math.max(
          1,
          Math.ceil((new Date(active.expiresAt).getTime() - Date.now()) / 60_000)
        );
        await this.whatsapp.sendText(
          phone,
          `⏳ Você possui um Pix ativo de *${formatBrl(active.amountBrl)}* válido por mais *${remainingMin} min*.\n\nDigite *1* para reenviar o código ou *2* para cancelar e gerar outro valor.`
        );
        session.stage = 'AWAITING_ACTIVE_ORDER_DECISION';
        this.repository.saveSession(session);
        return;
      }
    }

    // Decisão sobre cobrança ativa ainda válida
    if (session.stage === 'AWAITING_ACTIVE_ORDER_DECISION') {
      const active = this.repository.findActivePendingOrderByPhone(phone);
      if (!active) {
        session.stage = 'IDLE';
      } else if (lower === '1' || lower.includes('reenviar') || lower.includes('mesmo')) {
        session.stage = 'IDLE';
        this.repository.saveSession(session);
        await this.resendActiveOrder(active);
        return;
      } else if (lower === '2' || lower.includes('novo') || lower.includes('outro')) {
        this.repository.updateOrderStatus(active.id, 'CANCELLED');
        if (session.pendingNewAmountBrl) {
          const amount = session.pendingNewAmountBrl;
          session.pendingNewAmountBrl = undefined;
          await this.proceedWithAmount(phone, amount);
          return;
        }
        session.stage = 'AWAITING_AMOUNT';
        this.repository.saveSession(session);
        await this.whatsapp.sendText(
          phone,
          '🔄 Chave anterior cancelada! Qual o *novo valor em Reais* para o Pix? (Ex: *200,00*)'
        );
        return;
      }
    }

    // Evita gerar duas chaves simultâneas sem querer enquanto uma ainda está válida
    const activeOrder = this.repository.findActivePendingOrderByPhone(phone);
    if (activeOrder && session.stage === 'IDLE') {
      const possibleNewAmount = parseBrlAmountFromText(text);
      const remainingMin = Math.max(
        1,
        Math.ceil((new Date(activeOrder.expiresAt).getTime() - Date.now()) / 60_000)
      );

      session.stage = 'AWAITING_ACTIVE_ORDER_DECISION';
      session.pendingNewAmountBrl = possibleNewAmount ?? undefined;
      this.repository.saveSession(session);

      await this.whatsapp.sendText(
        phone,
        `⚠️ Você já tem uma chave Pix ativa de *${formatBrl(activeOrder.amountBrl)}* válida por mais *${remainingMin} min*.\n\n` +
          `*1* - Reenviar a chave Pix atual (${formatBrl(activeOrder.amountBrl)})\n` +
          `*2* - Cancelar a anterior e gerar uma nova chave`
      );
      return;
    }

    // Estágio opcional (apenas caso o provedor específico exija documento)
    if (session.stage === 'AWAITING_DOCUMENT' && session.draftAmountBrl) {
      const docCheck = validateAndCleanDocument(text);
      if (!docCheck.valid) {
        await this.whatsapp.sendText(
          phone,
          '❌ Documento inválido. Digite os 11 dígitos do CPF ou 14 do CNPJ (ou digite *cancelar*):'
        );
        return;
      }

      await this.generateAndDeliverPix({
        phone,
        amountBrl: session.draftAmountBrl,
        payerDocument: docCheck.digits,
      });
      return;
    }

    // Detecta o valor direto (ex: "Pix de 150" ou "150,00") e já gera sem burocracia!
    const detectedAmount = parseBrlAmountFromText(text);
    if (detectedAmount !== null) {
      await this.proceedWithAmount(phone, detectedAmount);
      return;
    }

    // Se mandou apenas "Oi" / "Me passa o Pix", solicita somente o valor!
    session.stage = 'AWAITING_AMOUNT';
    this.repository.saveSession(session);

    await this.whatsapp.sendText(
      phone,
      `Olá! ⚡ Bem-vindo ao pagamento automático via *Pix*.\n\n` +
        `Qual o *valor em Reais* que você deseja pagar? _(Ex: 150,00)_`
    );
  }

  private async proceedWithAmount(phone: string, amountBrl: number): Promise<void> {
    const mustAskDoc = this.config.requirePayerDocument || this.cryptoProvider.requiresPayerDocument;

    if (mustAskDoc) {
      this.repository.saveSession({
        phone,
        stage: 'AWAITING_DOCUMENT',
        draftAmountBrl: amountBrl,
        updatedAt: new Date().toISOString(),
      });

      await this.whatsapp.sendText(
        phone,
        `💰 Valor: *${formatBrl(amountBrl)}*.\nDigite o CPF/CNPJ pagador para liberar a chave:`
      );
      return;
    }

    // Modo Privacidade Padrão: NÃO pede nome nem CPF! Gera a chave Pix imediatamente!
    await this.generateAndDeliverPix({
      phone,
      amountBrl,
    });
  }

  private async generateAndDeliverPix(params: {
    phone: string;
    amountBrl: number;
    payerDocument?: string;
  }): Promise<void> {
    const orderId = crypto.randomUUID();
    const externalId = `ord_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const webhookUrl = `${this.config.publicBaseUrl}/webhooks/${this.cryptoProvider.name}`;

    try {
      const charge = await this.cryptoProvider.createCharge({
        externalId,
        amountBrl: params.amountBrl,
        customerPhone: params.phone,
        payerDocument: params.payerDocument,
        walletAddress: this.config.walletAddress,
        cryptoAsset: this.config.walletAsset,
        cryptoNetwork: this.config.walletNetwork,
        expirationMinutes: this.config.pixExpirationMinutes,
        webhookUrl,
      });

      const order: PixCryptoOrder = {
        id: orderId,
        externalId,
        provider: this.cryptoProvider.name,
        providerChargeId: charge.providerChargeId,
        customerPhone: params.phone,
        payerDocument: params.payerDocument,
        amountBrl: params.amountBrl,
        estimatedCryptoAmount: charge.estimatedCryptoAmount,
        cryptoAsset: this.config.walletAsset,
        cryptoNetwork: this.config.walletNetwork,
        walletAddress: this.config.walletAddress,
        pixCopyPaste: charge.pixCopyPaste,
        pixQrCodeBase64: charge.pixQrCodeBase64,
        pixQrCodeUrl: charge.pixQrCodeUrl,
        paymentUrl: charge.paymentUrl,
        status: 'PENDING',
        warningSent: false,
        createdAt: new Date().toISOString(),
        expiresAt: charge.expiresAt,
      };

      this.repository.createOrder(order);

      this.repository.saveSession({
        phone: params.phone,
        stage: 'IDLE',
        updatedAt: new Date().toISOString(),
      });

      const expiresDate = new Date(order.expiresAt);
      const timeStr = expiresDate.toLocaleTimeString('pt-BR', {
        hour: '2-digit',
        minute: '2-digit',
      });
      const validMinutes = Math.max(
        1,
        Math.round((expiresDate.getTime() - Date.now()) / 60_000)
      );

      const docLine = params.payerDocument
        ? `👤 *Titular:* ${maskDocument(params.payerDocument)}\n`
        : '';

      const summaryText =
        `✅ *Chave Pix Gerada na Hora!*\n\n` +
        `💵 *Valor:* ${formatBrl(order.amountBrl)}\n` +
        docLine +
        `⏳ *Validade:* ${validMinutes} minutos (vence às *${timeStr}*)\n\n` +
        `👇 *Copie o código Pix Copia e Cola na mensagem abaixo* ou escaneie o QR Code:`;

      await this.whatsapp.sendPixCharge({
        phone: params.phone,
        summaryText,
        pixCopyPaste: order.pixCopyPaste,
        qrCodeBase64: order.pixQrCodeBase64,
        qrCodeUrl: order.pixQrCodeUrl,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('[ConversationEngine] Erro ao gerar Pix:', msg);
      await this.whatsapp.sendText(
        params.phone,
        `⚠️ Instabilidade temporária ao gerar a chave Pix. Por favor, envie o valor novamente em alguns segundos.`
      );
    }
  }

  private async resendActiveOrder(order: PixCryptoOrder): Promise<void> {
    const expiresDate = new Date(order.expiresAt);
    const timeStr = expiresDate.toLocaleTimeString('pt-BR', {
      hour: '2-digit',
      minute: '2-digit',
    });
    const remainingMin = Math.max(1, Math.ceil((expiresDate.getTime() - Date.now()) / 60_000));

    const summaryText =
      `🔄 *Sua Chave Pix Ativa*\n\n` +
      `💵 *Valor:* ${formatBrl(order.amountBrl)}\n` +
      `⏳ *Tempo restante:* ${remainingMin} min (vence às *${timeStr}*)\n\n` +
      `👇 Copie o código Pix abaixo:`;

    await this.whatsapp.sendPixCharge({
      phone: order.customerPhone,
      summaryText,
      pixCopyPaste: order.pixCopyPaste,
      qrCodeBase64: order.pixQrCodeBase64,
      qrCodeUrl: order.pixQrCodeUrl,
    });
  }

  public async handleSettlementWebhook(event: WebhookSettlementEvent): Promise<{
    matched: boolean;
    changed: boolean;
    order?: PixCryptoOrder;
  }> {
    const existing = this.repository.findOrderByWebhookIds({
      provider: event.provider,
      providerChargeId: event.providerChargeId,
      externalId: event.externalId,
    });

    if (!existing) {
      return { matched: false, changed: false };
    }

    const { changed, updatedOrder } = this.repository.applySettlementUpdate({
      orderId: existing.id,
      newStatus: event.newStatus,
      txHash: event.txHash,
      endToEndId: event.endToEndId,
      cryptoAmount: event.cryptoAmount,
    });

    if (!changed || !updatedOrder) {
      return { matched: true, changed: false, order: existing };
    }

    if (updatedOrder.status === 'PIX_CONFIRMED') {
      await this.whatsapp.sendText(
        updatedOrder.customerPhone,
        `🎉 *Pix de ${formatBrl(updatedOrder.amountBrl)} identificado!* Finalizando confirmação...`
      );
    } else if (updatedOrder.status === 'SETTLED_CRYPTO') {
      await this.whatsapp.sendText(
        updatedOrder.customerPhone,
        `✅ *Pagamento de ${formatBrl(updatedOrder.amountBrl)} Confirmado!*\n\n` +
          `🧾 *Protocolo:* \`${updatedOrder.externalId}\`\n` +
          `Obrigado!`
      );

      if (
        this.config.adminWhatsappPhone &&
        this.config.adminWhatsappPhone !== updatedOrder.customerPhone
      ) {
        const cryptoAmt = updatedOrder.estimatedCryptoAmount
          ? `${updatedOrder.estimatedCryptoAmount} ${updatedOrder.cryptoAsset}`
          : updatedOrder.cryptoAsset;
        const hashLine = updatedOrder.txHash ? `\n🔗 *TxHash:* \`${updatedOrder.txHash}\`` : '';

        await this.whatsapp.sendText(
          this.config.adminWhatsappPhone,
          `🚀 *Cripto Liquidada Direto na Carteira!*\n\n` +
            `💵 *Pix Pago:* ${formatBrl(updatedOrder.amountBrl)}\n` +
            `🪙 *Recebido:* ~${cryptoAmt} (${updatedOrder.cryptoNetwork})` +
            hashLine
        );
      }
    } else if (updatedOrder.status === 'FAILED') {
      await this.whatsapp.sendText(
        updatedOrder.customerPhone,
        `⚠️ O pagamento da chave *${updatedOrder.externalId}* não pôde ser concluído. Envie o valor novamente para gerar uma nova chave.`
      );
    }

    return { matched: true, changed: true, order: updatedOrder };
  }
}
