import crypto from 'node:crypto';
import QRCode from 'qrcode';
import type {
  CreateChargeInput,
  CreateChargeOutput,
  IPixCryptoProvider,
  OrderStatus,
  WebhookSettlementEvent,
} from '../types/domain.ts';

export class PixGoProvider implements IPixCryptoProvider {
  public readonly name = 'pixgo' as const;
  public readonly requiresPayerDocument = true;
  private readonly config: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
  };

  constructor(config: { apiUrl: string; apiKey: string; webhookSecret: string }) {
    this.config = config;
  }

  public async createCharge(input: CreateChargeInput): Promise<CreateChargeOutput> {
    if (!this.config.apiKey) {
      throw new Error('PIXGO_API_KEY não configurada no arquivo .env.');
    }
    if (!input.payerDocument) {
      throw new Error('A API PixGo exige receiver_cpf (use DePixAppProvider para operar sem CPF).');
    }

    const response = await fetch(`${this.config.apiUrl}/payment/create`, {
      method: 'POST',
      headers: {
        'X-API-Key': this.config.apiKey,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        amount: input.amountBrl,
        description: `Pagamento #${input.externalId}`,
        external_id: input.externalId,
        receiver_name: input.customerName || 'Cliente',
        receiver_cpf: input.payerDocument,
        receiver_phone: input.customerPhone,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Falha ao criar cobrança na PixGo (HTTP ${response.status}): ${errorText}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    const pixCopyPaste = String(data.qr_code ?? '');
    if (!pixCopyPaste) {
      throw new Error('A resposta da PixGo não retornou o campo qr_code.');
    }

    const expiresAt = data.expires_at
      ? String(data.expires_at)
      : new Date(Date.now() + input.expirationMinutes * 60_000).toISOString();

    const pixQrCodeBase64 = await QRCode.toDataURL(pixCopyPaste, { width: 320, margin: 2 });
    const feeEstimate = input.amountBrl >= 50 ? input.amountBrl * 0.02 : input.amountBrl * 0.02 + 1;
    const estimatedCryptoAmount = Math.max(0, Math.round((input.amountBrl - feeEstimate) * 100) / 100);

    return {
      providerChargeId: String(data.payment_id ?? input.externalId),
      pixCopyPaste,
      pixQrCodeBase64,
      pixQrCodeUrl: data.qr_image_url ? String(data.qr_image_url) : undefined,
      estimatedCryptoAmount,
      expiresAt,
    };
  }

  public verifyWebhookSignature(
    rawBody: string,
    headers: Record<string, string | string[] | undefined>
  ): boolean {
    const sig =
      headers['x-pixgo-signature'] ?? headers['x-webhook-signature'] ?? headers['x-signature'];
    if (!sig || typeof sig !== 'string' || !this.config.webhookSecret) {
      return false;
    }

    const expectedHex = crypto
      .createHmac('sha256', this.config.webhookSecret)
      .update(rawBody)
      .digest('hex');

    const cleanSig = sig.replace(/^sha256=/i, '').trim();
    const a = Buffer.from(cleanSig, 'utf8');
    const b = Buffer.from(expectedHex, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  public parseWebhookPayload(payload: unknown): WebhookSettlementEvent | null {
    if (!payload || typeof payload !== 'object') return null;
    const root = payload as Record<string, unknown>;
    const event = String(root.event || '');
    const data = (root.data || {}) as Record<string, unknown>;

    let newStatus: OrderStatus | null = null;
    if (event === 'payment.completed') {
      newStatus = 'SETTLED_CRYPTO';
    } else if (event === 'payment.expired') {
      newStatus = 'EXPIRED';
    } else if (event === 'payment.refunded') {
      newStatus = 'FAILED';
    }

    if (!newStatus) return null;

    return {
      provider: 'pixgo',
      providerChargeId: data.payment_id ? String(data.payment_id) : undefined,
      externalId: data.external_id ? String(data.external_id) : undefined,
      newStatus,
      txHash: data.tx_hash ? String(data.tx_hash) : undefined,
      cryptoAmount: data.net_amount != null ? Number(data.net_amount) : undefined,
      rawEventName: event,
    };
  }
}
