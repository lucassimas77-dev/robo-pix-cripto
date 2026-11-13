/**
 * Definições de tipos centrais do domínio de Automação Pix -> Cripto via WhatsApp
 * com foco em Privacidade, Autocustódia e Zero Identificação no Atendimento.
 */

export type OrderStatus =
  | 'PENDING'        // Aguardando pagamento do Pix dentro do prazo de validade
  | 'PIX_CONFIRMED'  // Pix pago pelo cliente; aguardando envio on-chain da cripto
  | 'SETTLED_CRYPTO' // Criptomoeda liquidada direto na carteira de autocustódia
  | 'EXPIRED'        // Prazo de validade do QR Code Pix encerrou sem pagamento
  | 'CANCELLED'      // Cancelado pelo usuário antes do pagamento
  | 'FAILED';        // Falha ou estorno na rota de liquidação

export type SupportedProviderName = 'mock' | 'depixapp' | 'hodle' | 'pixgo' | 'noxpay';

export interface PixCryptoOrder {
  id: string;
  externalId: string;
  provider: SupportedProviderName;
  providerChargeId: string;
  customerPhone: string;
  customerName?: string;
  payerDocument?: string; // Opcional (omitido por padrão para máxima privacidade)
  amountBrl: number;
  estimatedCryptoAmount?: number;
  cryptoAsset: string;
  cryptoNetwork: string;
  walletAddress: string;
  pixCopyPaste: string;
  pixQrCodeBase64?: string;
  pixQrCodeUrl?: string;
  paymentUrl?: string;
  status: OrderStatus;
  warningSent: boolean;
  txHash?: string;
  endToEndId?: string;
  createdAt: string; // ISO 8601
  expiresAt: string; // ISO 8601
  paidAt?: string;   // ISO 8601
}

export type ConversationStage =
  | 'IDLE'
  | 'AWAITING_AMOUNT'
  | 'AWAITING_DOCUMENT'
  | 'AWAITING_ACTIVE_ORDER_DECISION';

export interface ChatSession {
  phone: string;
  stage: ConversationStage;
  draftAmountBrl?: number;
  draftCustomerName?: string;
  pendingNewAmountBrl?: number;
  updatedAt: string;
}

export interface CreateChargeInput {
  externalId: string;
  amountBrl: number;
  customerPhone: string;
  customerName?: string;
  payerDocument?: string;
  walletAddress: string;
  cryptoAsset: string;
  cryptoNetwork: string;
  expirationMinutes: number;
  webhookUrl: string;
}

export interface CreateChargeOutput {
  providerChargeId: string;
  pixCopyPaste: string;
  pixQrCodeBase64?: string;
  pixQrCodeUrl?: string;
  paymentUrl?: string;
  estimatedCryptoAmount?: number;
  expiresAt: string; // ISO 8601
}

export interface WebhookSettlementEvent {
  provider: SupportedProviderName;
  providerChargeId?: string;
  externalId?: string;
  newStatus: OrderStatus;
  txHash?: string;
  endToEndId?: string;
  cryptoAmount?: number;
  rawEventName: string;
}

export interface IPixCryptoProvider {
  readonly name: SupportedProviderName;
  readonly requiresPayerDocument: boolean;

  /**
   * Cria uma nova cobrança Pix dinâmica vinculada à conversão automática para a carteira cripto.
   */
  createCharge(input: CreateChargeInput): Promise<CreateChargeOutput>;

  /**
   * Verifica a assinatura criptográfica (HMAC/SHA256) do webhook recebido.
   */
  verifyWebhookSignature(rawBody: string, headers: Record<string, string | string[] | undefined>): boolean;

  /**
   * Interpreta o payload JSON do provedor para o formato padronizado do sistema.
   */
  parseWebhookPayload(payload: unknown): WebhookSettlementEvent | null;

  /**
   * Consulta ativa de status na API (permite confirmar pagamentos automaticamente
   * mesmo sem o usuário precisar configurar URL de Webhook manualmente no provedor).
   */
  checkChargeStatus?(providerChargeId: string): Promise<{
    status: OrderStatus;
    txHash?: string;
    cryptoAmount?: number;
  } | null>;
}

export interface RuntimeAccountSettings {
  provider: SupportedProviderName;
  apiKey: string;
  webhookSecret: string;
  walletAddress: string;
  walletAsset: string;
  walletNetwork: string;
  pixExpirationMinutes: number;
  adminWhatsappPhone: string;
}

export interface OutgoingWhatsAppMessage {
  id?: number;
  phone: string;
  direction: 'INBOUND' | 'OUTBOUND';
  type: 'TEXT' | 'IMAGE' | 'PIX_CODE';
  body: string;
  mediaBase64?: string;
  mediaUrl?: string;
  createdAt: string;
}

export interface IWhatsAppGateway {
  sendText(phone: string, text: string): Promise<void>;
  sendPixCharge(params: {
    phone: string;
    summaryText: string;
    pixCopyPaste: string;
    qrCodeBase64?: string;
    qrCodeUrl?: string;
  }): Promise<void>;
}
