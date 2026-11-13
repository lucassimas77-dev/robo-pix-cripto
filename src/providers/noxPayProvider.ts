import crypto from 'node:crypto';
import QRCode from 'qrcode';
import type {
  CreateChargeInput,
  CreateChargeOutput,
  IPixCryptoProvider,
  OrderStatus,
  WebhookSettlementEvent,
} from '../types/domain.ts';

export class NoxPayProvider implements IPixCryptoProvider {
  public readonly name = 'noxpay' as const;
  public readonly requiresPayerDocument: boolean;
  private readonly config: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
    requiresPayerDocument?: boolean;
  };

  constructor(config: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
    requiresPayerDocument?: boolean;
  }) {
    this.config = config;
    this.requiresPayerDocument = config.requiresPayerDocument ?? false;
  }

  public async createCharge(input: CreateChargeInput): Promise<CreateChargeOutput> {
    if (!this.config.apiKey) {
      throw new Error('NOXPAY_API_KEY não configurada no arquivo .env.');
    }

    const bodyPayload: Record<string, unknown> = {
      currency_code: 'BRL_PIX',
      amount_fiat: input.amountBrl,
      crypto_currency: input.cryptoAsset.toUpperCase(),
      crypto_network: input.cryptoNetwork.toUpperCase(),
      wallet_address: input.walletAddress,
      external_id: input.externalId,
      webhook: input.webhookUrl,
    };
    if (input.payerDocument) bodyPayload.payer_document = input.payerDocument;
    if (input.customerName) bodyPayload.payer_name = input.customerName;

    const response = await fetch(`${this.config.apiUrl}/crossramp_checkout`, {
      method: 'POST',
      headers: {
        'api-key': this.config.apiKey,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(bodyPayload),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Falha ao criar cobrança na NoxPay (HTTP ${response.status}): ${errorText}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    const pixCopyPaste = String(data.pix_code ?? data.qr_code_text ?? data.brcode ?? '');
    if (!pixCopyPaste) {
      throw new Error('A resposta da NoxPay não retornou o código Pix Copia e Cola.');
    }

    const expiresAt = data.expires_at
      ? String(data.expires_at)
      : new Date(Date.now() + input.expirationMinutes * 60_000).toISOString();

    const pixQrCodeBase64 = await QRCode.toDataURL(pixCopyPaste, { width: 320, margin: 2 });

    return {
      providerChargeId: String(data.txid ?? data.id ?? input.externalId),
      pixCopyPaste,
      pixQrCodeBase64,
      estimatedCryptoAmount: data.amount_crypto != null ? Number(data.amount_crypto) : undefined,
      expiresAt,
    };
  }

  public verifyWebhookSignature(
    rawBody: string,
    headers: Record<string, string | string[] | undefined>
  ): boolean {
    const signature = headers['x-signature'];
    if (!signature || typeof signature !== 'string' || !this.config.webhookSecret) {
      return false;
    }

    const expectedBase64 = crypto
      .createHash('sha256')
      .update(this.config.webhookSecret + rawBody)
      .digest('base64');

    const a = Buffer.from(signature.trim(), 'utf8');
    const b = Buffer.from(expectedBase64, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  public parseWebhookPayload(payload: unknown): WebhookSettlementEvent | null {
    if (!payload || typeof payload !== 'object') return null;
    const obj = payload as Record<string, unknown>;
    const statusRaw = String(obj.status ?? '').toUpperCase();

    let newStatus: OrderStatus | null = null;
    if (statusRaw === 'PAID' || statusRaw === 'PIX_PAID') {
      newStatus = 'PIX_CONFIRMED';
    } else if (statusRaw === 'COMPLETED' || statusRaw === 'SETTLED') {
      newStatus = 'SETTLED_CRYPTO';
    } else if (statusRaw === 'EXPIRED') {
      newStatus = 'EXPIRED';
    } else if (statusRaw === 'FAILED' || statusRaw === 'REFUNDED') {
      newStatus = 'FAILED';
    }

    if (!newStatus) return null;

    return {
      provider: 'noxpay',
      providerChargeId: obj.txid ? String(obj.txid) : obj.id ? String(obj.id) : undefined,
      externalId: obj.external_id ? String(obj.external_id) : undefined,
      newStatus,
      txHash: obj.tx_hash ? String(obj.tx_hash) : undefined,
      cryptoAmount: obj.amount_crypto != null ? Number(obj.amount_crypto) : undefined,
      rawEventName: statusRaw,
    };
  }
}
