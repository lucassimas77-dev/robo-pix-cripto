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
  formatTimeSaoPaulo,
  onlyDigits,
  parseBrlAmountFromText,
} from '../utils/cpfCnpjValidator.ts';

/**
 * Motor Conversacional com Modo Fixo de Privacidade (Opção 1):
 * - NUNCA pede CPF, CNPJ nem nome na conversa do WhatsApp!
 * - Possui lock assíncrono por telefone (`phoneLocks`) impedindo cobranças duplicadas concorrentes.
 * - Exibe horários sempre em `America/Sao_Paulo` (horário de Brasília).
 */
export class ConversationEngine {
  private config: AppConfig;
  private readonly repository: OrderRepository;
  private cryptoProvider: IPixCryptoProvider;
  private readonly whatsapp: IWhatsAppGateway;
  private readonly phoneLocks = new Map<string, Promise<void>>();

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
    customerJid?: string;
    text: string;
    customerName?: string;
  }): Promise<void> {
    const phone = onlyDigits(params.phone);
    if (!phone || !params.text.trim()) return;

    // Serializa mensagens concorrentes do mesmo telefone para impedir criação dupla de Pix
    const prevLock = this.phoneLocks.get(phone) ?? Promise.resolve();
    const currentTask = prevLock
      .catch(() => {})
      .then(() => this.processSerializedMessage(phone, params.text.trim(), params.customerJid));

    this.phoneLocks.set(phone, currentTask);
    try {
      await currentTask;
    } finally {
      if (this.phoneLocks.get(phone) === currentTask) {
        this.phoneLocks.delete(phone);
      }
    }
  }

  private async processSerializedMessage(
    phone: string,
    text: string,
    customerJid?: string
  ): Promise<void> {
    this.repository.logMessage({
      phone,
      direction: 'INBOUND',
      type: 'TEXT',
      body: text,
      createdAt: new Date().toISOString(),
    });

    const lower = text.toLowerCase();
    const session = this.repository.getSession(phone);
    if (customerJid) {
      session.customerJid = customerJid;
    }

    // Comando global de cancelamento/reinício
    if (['cancelar', 'sair', 'reiniciar', 'reset'].includes(lower)) {
      const activeOrder = this.repository.findActivePendingOrderByPhone(phone);
      if (activeOrder) {
        this.repository.updateOrderStatus(activeOrder.id, 'CANCELLED');
        if (
          this.cryptoProvider.name === activeOrder.provider &&
          this.cryptoProvider.expireCharge
        ) {
          void this.cryptoProvider.expireCharge(activeOrder.providerChargeId);
        }
      }
      this.repository.saveSession({
        phone,
        customerJid: session.customerJid,
        stage: 'IDLE',
        updatedAt: new Date().toISOString(),
      });
      await this.whatsapp.sendText(
        phone,
        '✅ Atendimento reiniciado.\n\nPara gerar uma nova cobrança Pix imediata, basta enviar o *valor em Reais* (ex: *150,00*).',
        session.customerJid
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
        session.stage = 'AWAITING_ACTIVE_ORDER_DECISION';
        this.repository.saveSession(session);
        await this.whatsapp.sendText(
          phone,
          `⏳ Você possui um Pix ativo de *${formatBrl(active.amountBrl)}* válido por mais *${remainingMin} min*.\n\nDigite *1* para reenviar ou *2* para cancelar e gerar outro valor.`,
          session.customerJid
        );
        return;
      }
    }

    // Decisão estrita sobre cobrança ativa ainda válida (sem queda acidental para criação dupla!)
    if (session.stage === 'AWAITING_ACTIVE_ORDER_DECISION') {
      const active = this.repository.findActivePendingOrderByPhone(phone);

      if (!active) {
        // A cobrança expirou exatamente antes de o cliente responder "1" ou "2"
        session.stage = 'AWAITING_AMOUNT';
        session.pendingNewAmountBrl = undefined;
        this.repository.saveSession(session);

        if (lower === '1' || lower === '2') {
          await this.whatsapp.sendText(
            phone,
            '⏰ A cobrança anterior já expirou! Qual o *valor em Reais* que deseja gerar agora? _(Ex: 50,00)_',
            session.customerJid
          );
          return;
        }
        // Se digitou um valor real novo (ex: "150,00"), segue abaixo normalmente
      } else if (lower === '1' || lower.includes('reenviar') || lower.includes('mesmo')) {
        session.stage = 'IDLE';
        session.pendingNewAmountBrl = undefined;
        this.repository.saveSession(session);
        await this.resendActiveOrder(active);
        return;
      } else if (lower === '2' || lower.includes('novo') || lower.includes('outro')) {
        this.repository.updateOrderStatus(active.id, 'CANCELLED');
        if (
          this.cryptoProvider.name === active.provider &&
          this.cryptoProvider.expireCharge
        ) {
          void this.cryptoProvider.expireCharge(active.providerChargeId);
        }
        const pendingAmt = session.pendingNewAmountBrl;
        session.pendingNewAmountBrl = undefined;
        session.stage = 'IDLE';
        this.repository.saveSession(session);

        if (pendingAmt) {
          await this.proceedWithAmount(phone, pendingAmt, session.customerJid);
          return;
        }

        session.stage = 'AWAITING_AMOUNT';
        this.repository.saveSession(session);
        await this.whatsapp.sendText(
          phone,
          '🔄 Cobrança anterior cancelada! Qual o *novo valor em Reais* para o Pix? _(Ex: 200,00)_',
          session.customerJid
        );
        return;
      } else {
        // Qualquer outra resposta mantém a trava ativa sem criar 2º Pix paralelo!
        const newCandidateAmount = parseBrlAmountFromText(text);
        if (newCandidateAmount !== null) {
          session.pendingNewAmountBrl = newCandidateAmount;
          this.repository.saveSession(session);
        }
        const remainingMin = Math.max(
          1,
          Math.ceil((new Date(active.expiresAt).getTime() - Date.now()) / 60_000)
        );
        await this.whatsapp.sendText(
          phone,
          `⚠️ Você já tem uma cobrança Pix ativa de *${formatBrl(active.amountBrl)}* (vence em ${remainingMin} min).\n\nResponda apenas:\n*1* - Reenviar a cobrança atual\n*2* - Cancelar a atual e gerar ${newCandidateAmount ? formatBrl(newCandidateAmount) : 'um novo valor'}`,
          session.customerJid
        );
        return;
      }
    }

    // Evita gerar duas cobranças simultâneas enquanto já há uma válida
    const activeOrder = this.repository.findActivePendingOrderByPhone(phone);
    if (activeOrder) {
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
        `⚠️ Você já tem uma cobrança Pix ativa de *${formatBrl(activeOrder.amountBrl)}* válida por mais *${remainingMin} min*.\n\n` +
          `*1* - Reenviar a cobrança atual (${formatBrl(activeOrder.amountBrl)})\n` +
          `*2* - Cancelar a anterior e gerar ${possibleNewAmount ? formatBrl(possibleNewAmount) : 'um novo valor'}`,
        session.customerJid
      );
      return;
    }

    const detectedAmount = parseBrlAmountFromText(text);
    if (detectedAmount !== null) {
      await this.proceedWithAmount(phone, detectedAmount, session.customerJid);
      return;
    }

    session.stage = 'AWAITING_AMOUNT';
    this.repository.saveSession(session);

    await this.whatsapp.sendText(
      phone,
      `Olá! ⚡ Bem-vindo ao pagamento automático via *Pix*.\n\n` +
        `Qual o *valor total em Reais* que você deseja pagar? _(Ex: R$ 50,00)_`,
      session.customerJid
    );
  }

  private async proceedWithAmount(
    phone: string,
    amountBrl: number,
    customerJid?: string
  ): Promise<void> {
    const minBrl = this.cryptoProvider.minAmountBrl;
    const maxBrl = this.cryptoProvider.maxAmountBrl;

    if (amountBrl < minBrl) {
      await this.whatsapp.sendText(
        phone,
        `⚠️ O valor mínimo para pagamento via Pix é de *${formatBrl(minBrl)}*. Envie um valor a partir de *${formatBrl(minBrl)}*:`,
        customerJid
      );
      return;
    }
    if (amountBrl > maxBrl) {
      await this.whatsapp.sendText(
        phone,
        `⚠️ O valor máximo por cobrança Pix é de *${formatBrl(maxBrl)}*. Envie um valor até *${formatBrl(maxBrl)}*:`,
        customerJid
      );
      return;
    }

    await this.generateAndDeliverPix({
      phone,
      customerJid,
      amountBrl,
    });
  }

  private async generateAndDeliverPix(params: {
    phone: string;
    customerJid?: string;
    amountBrl: number;
  }): Promise<void> {
    const orderId = crypto.randomUUID();
    const externalId = `ord_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const webhookUrl = `${this.config.publicBaseUrl}/webhooks/${this.cryptoProvider.name}`;

    // Na DePix App a moeda e rede são sempre DEPIX / LIQUID vinculados à conta da chave API
    const effectiveAsset =
      this.cryptoProvider.name === 'depixapp' ? 'DEPIX' : this.config.walletAsset;
    const effectiveNetwork =
      this.cryptoProvider.name === 'depixapp' ? 'LIQUID' : this.config.walletNetwork;
    const effectiveWallet =
      this.cryptoProvider.name === 'depixapp'
        ? 'Carteira Liquid (Conta DePix App)'
        : this.config.walletAddress;

    try {
      const charge = await this.cryptoProvider.createCharge({
        externalId,
        amountBrl: params.amountBrl,
        customerPhone: params.phone,
        walletAddress: this.config.walletAddress,
        cryptoAsset: effectiveAsset,
        cryptoNetwork: effectiveNetwork,
        expirationMinutes: this.config.pixExpirationMinutes,
        webhookUrl,
      });

      const order: PixCryptoOrder = {
        id: orderId,
        externalId,
        provider: this.cryptoProvider.name,
        providerChargeId: charge.providerChargeId,
        customerPhone: params.phone,
        customerJid: params.customerJid,
        amountBrl: params.amountBrl,
        estimatedCryptoAmount: charge.estimatedCryptoAmount,
        cryptoAsset: effectiveAsset,
        cryptoNetwork: effectiveNetwork,
        walletAddress: effectiveWallet,
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
        customerJid: params.customerJid,
        stage: 'IDLE',
        updatedAt: new Date().toISOString(),
      });

      const timeStr = formatTimeSaoPaulo(order.expiresAt);
      const validMinutes = Math.max(
        1,
        Math.round((new Date(order.expiresAt).getTime() - Date.now()) / 60_000)
      );

      const isPaymentLink = order.pixCopyPaste.startsWith('http');
      const actionInstruction = isPaymentLink
        ? `👇 *Toque no link seguro abaixo* para abrir e pagar seu Pix na hora:`
        : `👇 *Copie o código Pix Copia e Cola na mensagem abaixo* ou escaneie o QR Code:`;

      const summaryText =
        `✅ *Cobrança Pix Pronta!*\n\n` +
        `💵 *Valor:* ${formatBrl(order.amountBrl)}\n` +
        `⏳ *Validade:* ${validMinutes} minutos (vence às *${timeStr}* - Brasília)\n\n` +
        actionInstruction;

      await this.whatsapp.sendPixCharge({
        phone: params.phone,
        preferredJid: params.customerJid,
        summaryText,
        pixCopyPaste: order.pixCopyPaste,
        qrCodeBase64: order.pixQrCodeBase64,
        qrCodeUrl: order.pixQrCodeUrl,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('[ConversationEngine] Erro ao gerar Pix:', msg);

      if (msg.includes('API_KEY_MISSING') || msg.includes('WALLET_MISSING')) {
        await this.whatsapp.sendText(
          params.phone,
          `⚠️ A conta recebedora ainda está sendo configurada no painel. Tente novamente em instantes.`,
          params.customerJid
        );
        return;
      }

      await this.whatsapp.sendText(
        params.phone,
        `⚠️ Não foi possível gerar a cobrança agora. Por favor, envie o valor novamente em alguns instantes.`,
        params.customerJid
      );
    }
  }

  private async resendActiveOrder(order: PixCryptoOrder): Promise<void> {
    const timeStr = formatTimeSaoPaulo(order.expiresAt);
    const remainingMin = Math.max(
      1,
      Math.ceil((new Date(order.expiresAt).getTime() - Date.now()) / 60_000)
    );
    const isPaymentLink = order.pixCopyPaste.startsWith('http');

    const summaryText =
      `🔄 *Sua Cobrança Pix Ativa*\n\n` +
      `💵 *Valor:* ${formatBrl(order.amountBrl)}\n` +
      `⏳ *Tempo restante:* ${remainingMin} min (vence às *${timeStr}* - Brasília)\n\n` +
      (isPaymentLink ? `👇 Toque no link seguro abaixo:` : `👇 Copie o código Pix abaixo:`);

    await this.whatsapp.sendPixCharge({
      phone: order.customerPhone,
      preferredJid: order.customerJid,
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
    if (event.eventId && !this.repository.tryRecordWebhookEvent(event.eventId)) {
      return { matched: true, changed: false };
    }

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
        `🎉 *Pagamento Pix de ${formatBrl(updatedOrder.amountBrl)} recebido!*\n\n` +
          `🧾 *Protocolo:* \`${updatedOrder.externalId}\`\n` +
          `Seu pagamento já foi registrado pela processadora e está em liquidação para a carteira.`,
        updatedOrder.customerJid
      );

      if (
        this.config.adminWhatsappPhone &&
        this.config.adminWhatsappPhone !== updatedOrder.customerPhone
      ) {
        await this.whatsapp.sendText(
          this.config.adminWhatsappPhone,
          `💰 *Pix Pago pelo Cliente!* (${formatBrl(updatedOrder.amountBrl)})\n` +
            `Protocolo: \`${updatedOrder.externalId}\` — Aguardando liquidação on-chain (${updatedOrder.cryptoAsset}/${updatedOrder.cryptoNetwork}).`
        );
      }
    } else if (updatedOrder.status === 'SETTLED_CRYPTO') {
      await this.whatsapp.sendText(
        updatedOrder.customerPhone,
        `✅ *Pagamento de ${formatBrl(updatedOrder.amountBrl)} Confirmado!*\n\n` +
          `🧾 *Protocolo:* \`${updatedOrder.externalId}\`\n` +
          `Obrigado!`,
        updatedOrder.customerJid
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
        `⚠️ O pagamento da cobrança *${updatedOrder.externalId}* foi cancelado ou estornado pela processadora. Para gerar uma nova cobrança, envie o valor desejado.`,
        updatedOrder.customerJid
      );
    }

    return { matched: true, changed: true, order: updatedOrder };
  }
}
