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
  isCancelCommand,
  isExitCommand,
  isHelpCommand,
  isPaymentConfirmationMessage,
  isStatusQueryMessage,
  onlyDigits,
  parseActiveOrderMenuReply,
  parseBrlAmountFromText,
} from '../utils/cpfCnpjValidator.ts';

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

  private deactivateOrderRemotely(order: PixCryptoOrder): void {
    if (order.remoteDeactivated) return;
    const activeProv = this.cryptoProvider;
    if (activeProv.name !== order.provider) {
      if (!(order.provider === 'depixapp' && order.providerChargeId.startsWith('prd_'))) {
        this.repository.markRemoteDeactivated(order.id);
      }
      return;
    }
    if (!activeProv.expireCharge) {
      this.repository.markRemoteDeactivated(order.id);
      return;
    }
    void activeProv
      .expireCharge(order.providerChargeId)
      .then((ok) => {
        if (ok) {
          this.repository.markRemoteDeactivated(order.id);
        }
      })
      .catch(() => {
        // Permanece `remote_deactivated = 0` para retentativa automática pelo ExpirationWatcher
      });
  }

  public async handleIncomingMessage(params: {
    phone: string;
    customerJid?: string;
    text: string;
    customerName?: string;
  }): Promise<void> {
    const phone = onlyDigits(params.phone);
    if (!phone || !params.text.trim()) return;

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

    const session = this.repository.getSession(phone);
    if (customerJid) {
      session.customerJid = customerJid;
    }

    // 1. Comando de encerrar atendimento (volta para IDLE)
    if (isExitCommand(text)) {
      const activeOrder = this.repository.findActivePendingOrderByPhone(phone);
      if (activeOrder) {
        this.repository.updateOrderStatus(activeOrder.id, 'CANCELLED');
        this.deactivateOrderRemotely(activeOrder);
      }
      this.repository.saveSession({
        phone,
        customerJid: session.customerJid,
        stage: 'IDLE',
        updatedAt: new Date().toISOString(),
      });
      await this.safeSendText(
        phone,
        '✅ Atendimento encerrado. Quando precisar de um novo Pix, basta enviar uma mensagem!',
        session.customerJid
      );
      return;
    }

    // 2. Comando de reiniciar/cancelar mantendo escuta ativa (`AWAITING_AMOUNT`)
    if (isCancelCommand(text)) {
      const activeOrder = this.repository.findActivePendingOrderByPhone(phone);
      if (activeOrder) {
        this.repository.updateOrderStatus(activeOrder.id, 'CANCELLED');
        this.deactivateOrderRemotely(activeOrder);
      }
      this.repository.saveSession({
        phone,
        customerJid: session.customerJid,
        stage: 'AWAITING_AMOUNT',
        updatedAt: new Date().toISOString(),
      });
      await this.safeSendText(
        phone,
        '✅ Cobrança cancelada.\n\nEnvie agora o *novo valor em Reais* desejado (ex: *150,00*) ou envie *sair* para encerrar:',
        session.customerJid
      );
      return;
    }

    // 3. Mensagens pós-pagamento ("já paguei", "paguei 50 no pix", "status", "comprovante") NUNCA geram nova cobrança!
    if (isStatusQueryMessage(text) || isPaymentConfirmationMessage(text)) {
      session.pendingNewAmountBrl = undefined;
      session.draftAmountBrl = undefined;
      const recent = this.repository.findMostRecentOrderByPhone(phone);
      if (!recent) {
        session.stage = 'AWAITING_AMOUNT';
        this.repository.saveSession(session);
        await this.safeSendText(
          phone,
          `ℹ️ Não encontrei nenhuma cobrança registrada recentemente para este número.\n\nSe desejar gerar um novo Pix, envie apenas o *valor em Reais* (ex: *50,00*):`,
          session.customerJid
        );
        return;
      }

      if (recent.status === 'SETTLED_CRYPTO') {
        if (session.stage === 'AWAITING_ACTIVE_ORDER_DECISION') {
          session.stage = 'IDLE';
          this.repository.saveSession(session);
        }
        await this.safeSendText(
          phone,
          `✅ Seu pagamento de *${formatBrl(recent.amountBrl)}* (protocolo \`${recent.externalId}\`) já está *100% confirmado*!`,
          session.customerJid
        );
        return;
      }

      if (recent.status === 'PIX_CONFIRMED') {
        if (session.stage === 'AWAITING_ACTIVE_ORDER_DECISION') {
          session.stage = 'IDLE';
          this.repository.saveSession(session);
        }
        await this.safeSendText(
          phone,
          `🎉 Seu pagamento de *${formatBrl(recent.amountBrl)}* já foi recebido pela processadora e está em liquidação final!`,
          session.customerJid
        );
        return;
      }

      if (recent.status === 'PENDING' && new Date(recent.expiresAt).getTime() > Date.now()) {
        if (session.stage === 'AWAITING_ACTIVE_ORDER_DECISION') {
          session.stage = 'IDLE';
          this.repository.saveSession(session);
        }
        await this.safeSendText(
          phone,
          `⏳ Sua cobrança de *${formatBrl(recent.amountBrl)}* (\`${recent.externalId}\`) está aguardando compensação bancária. Assim que confirmar, aviso você automaticamente aqui mesmo!`,
          session.customerJid
        );
        return;
      }

      if (recent.status === 'EXPIRED' || recent.status === 'PENDING') {
        session.stage = 'AWAITING_AMOUNT';
        this.repository.saveSession(session);
        await this.safeSendText(
          phone,
          `⏰ Sua última cobrança de *${formatBrl(recent.amountBrl)}* (\`${recent.externalId}\`) consta com o prazo encerrado. Se você pagou antes do vencimento, aguarde alguns instantes pela compensação; caso não tenha pago e queira gerar outra, envie apenas o *valor em Reais*:`,
          session.customerJid
        );
        return;
      }

      session.stage = 'AWAITING_AMOUNT';
      this.repository.saveSession(session);
      await this.safeSendText(
        phone,
        `⚠️ Sua última cobrança de *${formatBrl(recent.amountBrl)}* (\`${recent.externalId}\`) consta como *${recent.status === 'FAILED' ? 'cancelada/estornada' : 'cancelada'}*.\n\nSe desejar gerar uma nova cobrança, envie apenas o *valor em Reais*:`,
        session.customerJid
      );
      return;
    }

    // 4. Comando de ajuda / instruções
    if (isHelpCommand(text) && parseBrlAmountFromText(text) === null) {
      const minStr = formatBrl(this.cryptoProvider.minAmountBrl);
      const maxStr = formatBrl(this.cryptoProvider.maxAmountBrl);
      const activeForHelp = this.repository.findActivePendingOrderByPhone(phone);
      if (!activeForHelp) {
        session.stage = 'AWAITING_AMOUNT';
        this.repository.saveSession(session);
      }
      await this.safeSendText(
        phone,
        `ℹ️ *Como funciona o Pix Automático:*\n\n` +
          `1️⃣ Envie o *valor em Reais* desejado (de *${minStr}* a *${maxStr}*, ex: *Pix de 50*)\n` +
          `2️⃣ Você recebe na hora o link seguro único + QR Code para pagar\n` +
          `3️⃣ Assim que o Pix compensar, envio a confirmação automática aqui!\n\n` +
          `_Comandos úteis:_ *status* (consultar pagamento), *cancelar* (trocar valor) ou *sair*.`,
        session.customerJid
      );
      return;
    }

    // 5. Decisão sobre cobrança ativa
    if (session.stage === 'AWAITING_ACTIVE_ORDER_DECISION') {
      const active = this.repository.findActivePendingOrderByPhone(phone);
      const menuReply = parseActiveOrderMenuReply(text);

      if (!active) {
        const prevPendingAmt = session.pendingNewAmountBrl;
        session.stage = 'AWAITING_AMOUNT';
        session.pendingNewAmountBrl = undefined;
        session.draftAmountBrl = undefined;
        this.repository.saveSession(session);

        if (menuReply.inlineNewAmountBrl !== null) {
          await this.proceedWithAmount(phone, menuReply.inlineNewAmountBrl, session.customerJid);
          return;
        }
        if (menuReply.choice === 'new' && prevPendingAmt) {
          await this.proceedWithAmount(phone, prevPendingAmt, session.customerJid);
          return;
        }

        await this.safeSendText(
          phone,
          '⏰ A cobrança anterior já expirou! Qual o *valor em Reais* que deseja gerar agora? _(Ex: 50,00)_',
          session.customerJid
        );
        return;
      }

      if (menuReply.choice === 'resend') {
        session.stage = 'IDLE';
        session.pendingNewAmountBrl = undefined;
        session.draftAmountBrl = undefined;
        this.repository.saveSession(session);
        await this.resendActiveOrder(active);
        return;
      }

      if (menuReply.choice === 'new') {
        this.repository.updateOrderStatus(active.id, 'CANCELLED');
        this.deactivateOrderRemotely(active);

        const targetAmt = menuReply.inlineNewAmountBrl ?? session.pendingNewAmountBrl;

        session.pendingNewAmountBrl = undefined;
        session.draftAmountBrl = undefined;
        session.stage = 'AWAITING_AMOUNT';
        this.repository.saveSession(session);

        if (targetAmt) {
          await this.proceedWithAmount(phone, targetAmt, session.customerJid);
          return;
        }

        await this.safeSendText(
          phone,
          '🔄 Cobrança anterior cancelada! Qual o *novo valor em Reais* para o Pix? _(Ex: 200,00)_',
          session.customerJid
        );
        return;
      }

      const newCandidateAmount = menuReply.inlineNewAmountBrl;
      if (newCandidateAmount !== null) {
        session.pendingNewAmountBrl = newCandidateAmount;
        this.repository.saveSession(session);
      }
      const effectiveCandidate = newCandidateAmount ?? session.pendingNewAmountBrl;
      const remainingMin = Math.max(
        1,
        Math.ceil((new Date(active.expiresAt).getTime() - Date.now()) / 60_000)
      );
      await this.safeSendText(
        phone,
        `⚠️ Você já tem uma cobrança Pix ativa de *${formatBrl(active.amountBrl)}* (vence em ${remainingMin} min).\n\nResponda apenas:\n*1* - Reenviar a cobrança atual\n*2* - Cancelar a atual e gerar ${effectiveCandidate ? formatBrl(effectiveCandidate) : 'um novo valor'}`,
        session.customerJid
      );
      return;
    }

    const activeOrder = this.repository.findActivePendingOrderByPhone(phone);
    if (activeOrder) {
      const possibleNewAmount = parseBrlAmountFromText(text);
      const remainingMin = Math.max(
        1,
        Math.ceil((new Date(activeOrder.expiresAt).getTime() - Date.now()) / 60_000)
      );

      session.stage = 'AWAITING_ACTIVE_ORDER_DECISION';
      session.pendingNewAmountBrl = possibleNewAmount ?? undefined;
      session.draftAmountBrl = undefined;
      this.repository.saveSession(session);

      await this.safeSendText(
        phone,
        `⚠️ Você já tem uma cobrança Pix ativa de *${formatBrl(activeOrder.amountBrl)}* válida por mais *${remainingMin} min*.\n\n` +
          `*1* - Reenviar a cobrança atual (${formatBrl(activeOrder.amountBrl)})\n` +
          `*2* - Cancelar a anterior e gerar ${possibleNewAmount ? formatBrl(possibleNewAmount) : 'um novo valor'}`,
        session.customerJid
      );
      return;
    }

    // Se o cliente estava diante do menu 1 / 2 no exato segundo em que a cobrança anterior expirou/falhou:
    if (session.draftAmountBrl === -1 || session.pendingNewAmountBrl !== undefined) {
      const menuAfterExp = parseActiveOrderMenuReply(text);
      const savedPendingAmt = session.pendingNewAmountBrl;
      const hadExpiredMenu = session.draftAmountBrl === -1;

      session.draftAmountBrl = undefined;
      session.pendingNewAmountBrl = undefined;
      this.repository.saveSession(session);

      if (menuAfterExp.choice === 'new') {
        const targetAmt = menuAfterExp.inlineNewAmountBrl ?? savedPendingAmt;
        if (targetAmt) {
          await this.proceedWithAmount(phone, targetAmt, session.customerJid);
          return;
        }
        await this.safeSendText(
          phone,
          '⏰ A cobrança anterior já expirou! Qual o *novo valor em Reais* para o Pix? _(Ex: 200,00)_',
          session.customerJid
        );
        return;
      }

      if (menuAfterExp.choice === 'resend' && hadExpiredMenu) {
        await this.safeSendText(
          phone,
          '⏰ A cobrança anterior já expirou! Qual o *valor em Reais* que deseja gerar agora? _(Ex: 50,00)_',
          session.customerJid
        );
        return;
      }
    }

    const detectedAmount = parseBrlAmountFromText(text);
    if (detectedAmount !== null) {
      await this.proceedWithAmount(phone, detectedAmount, session.customerJid);
      return;
    }

    session.stage = 'AWAITING_AMOUNT';
    this.repository.saveSession(session);

    await this.safeSendText(
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
      this.repository.saveSession({
        phone,
        customerJid,
        stage: 'AWAITING_AMOUNT',
        updatedAt: new Date().toISOString(),
      });
      await this.safeSendText(
        phone,
        `⚠️ O valor mínimo para pagamento via Pix é de *${formatBrl(minBrl)}*. Envie um valor a partir de *${formatBrl(minBrl)}*:`,
        customerJid
      );
      return;
    }

    if (amountBrl > maxBrl) {
      this.repository.saveSession({
        phone,
        customerJid,
        stage: 'AWAITING_AMOUNT',
        updatedAt: new Date().toISOString(),
      });
      await this.safeSendText(
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
    // Captura snapshot imutável do provedor e config antes do `await` contra troca concorrente em `/api/account`!
    const providerSnapshot = this.cryptoProvider;
    const configSnapshot = this.config;

    const orderId = crypto.randomUUID();
    const externalId = `ord_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const webhookUrl = `${configSnapshot.publicBaseUrl}/webhooks/${providerSnapshot.name}`;

    const effectiveAsset =
      providerSnapshot.name === 'depixapp' ? 'DEPIX' : configSnapshot.walletAsset;
    const effectiveNetwork =
      providerSnapshot.name === 'depixapp' ? 'LIQUID' : configSnapshot.walletNetwork;
    const effectiveWallet =
      providerSnapshot.name === 'depixapp'
        ? 'Carteira Liquid (Conta DePix App)'
        : configSnapshot.walletAddress;

    try {
      const charge = await providerSnapshot.createCharge({
        externalId,
        amountBrl: params.amountBrl,
        customerPhone: params.phone,
        walletAddress: configSnapshot.walletAddress,
        cryptoAsset: effectiveAsset,
        cryptoNetwork: effectiveNetwork,
        expirationMinutes: configSnapshot.pixExpirationMinutes,
        webhookUrl,
      });

      const needsRemoteDeactivation =
        providerSnapshot.name === 'depixapp' && charge.providerChargeId.startsWith('prd_');

      const order: PixCryptoOrder = {
        id: orderId,
        externalId,
        provider: providerSnapshot.name,
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
        remoteDeactivated: !needsRemoteDeactivation,
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

      await this.safeSendPixCharge({
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

      // Mantém AWAITING_AMOUNT para que nova tentativa sem repetir "pix" seja atendida!
      this.repository.saveSession({
        phone: params.phone,
        customerJid: params.customerJid,
        stage: 'AWAITING_AMOUNT',
        updatedAt: new Date().toISOString(),
      });

      if (msg.includes('API_KEY_MISSING') || msg.includes('WALLET_MISSING')) {
        await this.safeSendText(
          params.phone,
          `⚠️ A conta recebedora ainda está sendo configurada no painel. Tente novamente em instantes.`,
          params.customerJid
        );
        return;
      }

      if (msg.includes('RATE_LIMITED')) {
        await this.safeSendText(
          params.phone,
          `⏳ Estamos processando muitas solicitações simultâneas neste instante. Envie o valor novamente em alguns segundos!`,
          params.customerJid
        );
        return;
      }

      await this.safeSendText(
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

    await this.safeSendPixCharge({
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
    if (event.eventId && this.repository.hasWebhookEvent(event.eventId)) {
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
      eventId: event.eventId,
      newStatus: event.newStatus,
      txHash: event.txHash,
      endToEndId: event.endToEndId,
      cryptoAmount: event.cryptoAmount,
    });

    if (!changed || !updatedOrder) {
      return { matched: true, changed: false, order: existing };
    }

    if (updatedOrder.status === 'PIX_CONFIRMED' || updatedOrder.status === 'SETTLED_CRYPTO') {
      const otherActive = this.repository.findActivePendingOrderByPhone(updatedOrder.customerPhone);
      if (!otherActive) {
        const sess = this.repository.getSession(updatedOrder.customerPhone);
        if (sess.stage === 'AWAITING_ACTIVE_ORDER_DECISION' || sess.pendingNewAmountBrl !== undefined) {
          this.repository.saveSession({
            phone: updatedOrder.customerPhone,
            customerJid: updatedOrder.customerJid ?? sess.customerJid,
            stage: 'IDLE',
            updatedAt: new Date().toISOString(),
          });
        }
      }
    }

    if (updatedOrder.status === 'PIX_CONFIRMED') {
      await this.safeSendText(
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
        await this.safeSendText(
          this.config.adminWhatsappPhone,
          `💰 *Pix Pago pelo Cliente!* (${formatBrl(updatedOrder.amountBrl)})\n` +
            `Protocolo: \`${updatedOrder.externalId}\` — Aguardando liquidação on-chain (${updatedOrder.cryptoAsset}/${updatedOrder.cryptoNetwork}).`
        );
      }
    } else if (updatedOrder.status === 'SETTLED_CRYPTO') {
      await this.safeSendText(
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

        await this.safeSendText(
          this.config.adminWhatsappPhone,
          `🚀 *Cripto Liquidada Direto na Carteira!*\n\n` +
            `💵 *Pix Pago:* ${formatBrl(updatedOrder.amountBrl)}\n` +
            `🪙 *Recebido:* ~${cryptoAmt} (${updatedOrder.cryptoNetwork})` +
            hashLine
        );
      }
    } else if (updatedOrder.status === 'FAILED') {
      this.deactivateOrderRemotely(updatedOrder);

      const otherActive = this.repository.findActivePendingOrderByPhone(updatedOrder.customerPhone);
      if (!otherActive) {
        const sess = this.repository.getSession(updatedOrder.customerPhone);
        const hadDecisionMenu = sess.stage === 'AWAITING_ACTIVE_ORDER_DECISION';
        this.repository.saveSession({
          phone: updatedOrder.customerPhone,
          customerJid: updatedOrder.customerJid ?? sess.customerJid,
          stage: 'AWAITING_AMOUNT',
          draftAmountBrl: hadDecisionMenu ? -1 : undefined,
          pendingNewAmountBrl: hadDecisionMenu ? sess.pendingNewAmountBrl : undefined,
          updatedAt: new Date().toISOString(),
        });
      }

      await this.safeSendText(
        updatedOrder.customerPhone,
        `⚠️ O pagamento da cobrança *${updatedOrder.externalId}* foi cancelado ou estornado pela processadora. Para gerar uma nova cobrança, envie o valor desejado.`,
        updatedOrder.customerJid
      );

      if (
        this.config.adminWhatsappPhone &&
        this.config.adminWhatsappPhone !== updatedOrder.customerPhone
      ) {
        await this.safeSendText(
          this.config.adminWhatsappPhone,
          `❌ *Atenção: Pagamento Estornado/Cancelado!* (${formatBrl(updatedOrder.amountBrl)})\n` +
            `Protocolo: \`${updatedOrder.externalId}\` — A processadora recusou/estornou o pagamento.`
        );
      }
    } else if (updatedOrder.status === 'EXPIRED') {
      this.deactivateOrderRemotely(updatedOrder);

      const otherActive = this.repository.findActivePendingOrderByPhone(updatedOrder.customerPhone);
      const mostRecent = this.repository.findMostRecentOrderByPhone(updatedOrder.customerPhone);
      const hasNewerOrder =
        Boolean(otherActive) ||
        Boolean(
          mostRecent &&
            mostRecent.id !== updatedOrder.id &&
            mostRecent.createdAt >= updatedOrder.createdAt
        );

      if (!hasNewerOrder) {
        const sess = this.repository.getSession(updatedOrder.customerPhone);
        const hadDecisionMenu = sess.stage === 'AWAITING_ACTIVE_ORDER_DECISION';
        this.repository.saveSession({
          phone: updatedOrder.customerPhone,
          customerJid: updatedOrder.customerJid ?? sess.customerJid,
          stage: 'AWAITING_AMOUNT',
          draftAmountBrl: hadDecisionMenu ? -1 : undefined,
          pendingNewAmountBrl: hadDecisionMenu ? sess.pendingNewAmountBrl : undefined,
          updatedAt: new Date().toISOString(),
        });

        await this.safeSendText(
          updatedOrder.customerPhone,
          `⏰ *Atenção: A cobrança Pix de ${formatBrl(updatedOrder.amountBrl)} expirou.*\n\n` +
            `Não realize o pagamento em link/código vencido. Se quiser pagar agora, basta enviar o valor (*${updatedOrder.amountBrl.toFixed(2).replace('.', ',')}*) que gero uma nova na hora!`,
          updatedOrder.customerJid
        );
      }
    }

    return { matched: true, changed: true, order: updatedOrder };
  }

  private async safeSendText(phone: string, text: string, preferredJid?: string): Promise<void> {
    try {
      await this.whatsapp.sendText(phone, text, preferredJid);
    } catch (err) {
      console.error('[ConversationEngine] Falha ao enviar texto WhatsApp:', err);
    }
  }

  private async safeSendPixCharge(params: {
    phone: string;
    preferredJid?: string;
    summaryText: string;
    pixCopyPaste: string;
    qrCodeBase64?: string;
    qrCodeUrl?: string;
  }): Promise<void> {
    try {
      await this.whatsapp.sendPixCharge(params);
    } catch (err) {
      console.error('[ConversationEngine] Falha ao enviar cobrança WhatsApp:', err);
    }
  }
}
