/**
 * Definições de tipos centrais do domínio de Automação Pix -> Cripto via WhatsApp
 * (Modo Fixo: Zero Perguntas de Documento no WhatsApp).
 */

export type OrderStatus =
  | 'PENDING'        // Aguardando pagamento do Pix dentro do prazo de validade
  | 'PIX_CONFIRMED'  // Pix pago pelo cliente; em processamento/liquidação para a carteira
  | 'SETTLED_CRYPTO' // Criptomoeda liquidada direto na carteira de autocustódia
  | 'EXPIRED'        // Prazo de validade encerrou sem pagamento
  | 'CANCELLED'      // Cancelado pelo usuário antes do pagamento
  | 'FAILED';        // Falha ou estorno na rota de liquidação

export type SupportedProviderName = 'mock' | 'depixapp' | 'hodle' | 'noxpay';

export type FilterMode = 'keyword_only' | 'all';

export interface PixCryptoOrder {
  id: string;
  externalId: string;
  provider: SupportedProviderName;
  providerChargeId: string;
  customerPhone: string;
  customerJid?: string;
  customerName?: string;
  payerDocument?: string;
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
  | 'AWAITING_ACTIVE_ORDER_DECISION';

export interface ChatSession {
  phone: string;
  customerJid?: string;
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
  eventId?: string;
  providerChargeId?: string;
  externalId?: string;
  newStatus: OrderStatus;
  txHash?: string;
  endToEndId?: string;
  cryptoAmount?: number;
  rawEventName: string;
}

export interface ChargePollResult {
  status: OrderStatus;
  txHash?: string;
  cryptoAmount?: number;
  rejectionReasons?: string[];
  activePendingExpiresAt?: string; // Caso o cliente tenha acabado de abrir um QR no link privado
}

export interface IPixCryptoProvider {
  readonly name: SupportedProviderName;
  readonly minAmountBrl: number;
  readonly maxAmountBrl: number;

  createCharge(input: CreateChargeInput): Promise<CreateChargeOutput>;
  verifyWebhookSignature(
    rawBody: string,
    headers: Record<string, string | string[] | undefined>
  ): boolean;
  parseWebhookPayload(payload: unknown): WebhookSettlementEvent | null;
  checkChargeStatus(providerChargeId: string): Promise<ChargePollResult | null>;
  expireCharge?(providerChargeId: string): Promise<void>;
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
  adminPinHash?: string;
  waFilterMode?: FilterMode;
  waAllowedTestPhone?: string;
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
  sendText(phone: string, text: string, preferredJid?: string): Promise<void>;
  sendPixCharge(params: {
    phone: string;
    preferredJid?: string;
    summaryText: string;
    pixCopyPaste: string;
    qrCodeBase64?: string;
    qrCodeUrl?: string;
  }): Promise<void>;
}
