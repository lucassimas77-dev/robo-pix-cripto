import crypto from 'node:crypto';
import QRCode from 'qrcode';
import type {
  CreateChargeInput,
  CreateChargeOutput,
  IPixCryptoProvider,
  OrderStatus,
  WebhookSettlementEvent,
} from '../types/domain.ts';

export class HodleProvider implements IPixCryptoProvider {
  public readonly name = 'hodle' as const;
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
      throw new Error('HODLE_API_KEY não configurada no arquivo .env.');
    }

    let estimatedCryptoAmount: number | undefined;
    try {
      const quoteRes = await fetch(
        `${this.config.apiUrl}/api/quote?from=BRL&to=${encodeURIComponent(input.cryptoAsset)}&amount=${input.amountBrl}`,
        {
          headers: {
            Authorization: `Bearer ${this.config.apiKey}`,
            Accept: 'application/json',
          },
        }
      );
      if (quoteRes.ok) {
        const quoteData = (await quoteRes.json()) as Record<string, unknown>;
        if (quoteData.estimatedAmount != null || quoteData.amountOut != null) {
          estimatedCryptoAmount = Number(quoteData.estimatedAmount ?? quoteData.amountOut);
        }
      }
    } catch {
      // Prossegue normalmente caso o endpoint indicativo oscile
    }

    const bodyPayload: Record<string, unknown> = {
      externalId: input.externalId,
      amount: input.amountBrl.toFixed(2),
      asset: input.cryptoAsset.toUpperCase(),
      network: input.cryptoNetwork.toUpperCase(),
      destinationAddress: input.walletAddress,
      expirationMinutes: input.expirationMinutes,
      webhookUrl: input.webhookUrl,
    };
    if (input.payerDocument) bodyPayload.payerDocument = input.payerDocument;
    if (input.customerName) bodyPayload.payerName = input.customerName;

    const response = await fetch(`${this.config.apiUrl}/api/deposit/asset`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(bodyPayload),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Falha ao criar cobrança Pix na Hodle (HTTP ${response.status}): ${errorText}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    const pixCopyPaste = String(data.pixCopyPaste ?? data.qrCode ?? data.brcode ?? '');
    if (!pixCopyPaste) {
      throw new Error('Resposta da API Hodle não retornou o código Pix Copia e Cola.');
    }

    const expiresAt = data.expiresAt
      ? String(data.expiresAt)
      : new Date(Date.now() + input.expirationMinutes * 60_000).toISOString();

    const pixQrCodeBase64 = data.qrCodeBase64
      ? String(data.qrCodeBase64)
      : await QRCode.toDataURL(pixCopyPaste, { width: 320, margin: 2 });

    return {
      providerChargeId: String(data.id ?? data.depositId ?? input.externalId),
      pixCopyPaste,
      pixQrCodeBase64,
      estimatedCryptoAmount:
        data.assetAmount != null ? Number(data.assetAmount) : estimatedCryptoAmount,
      expiresAt,
    };
  }

  public verifyWebhookSignature(
    rawBody: string,
    headers: Record<string, string | string[] | undefined>
  ): boolean {
    const signatureHeader = headers['x-hodle-signature'];
    if (!signatureHeader || typeof signatureHeader !== 'string' || !this.config.webhookSecret) {
      return false;
    }

    const expectedHex = crypto
      .createHmac('sha256', this.config.webhookSecret)
      .update(rawBody)
      .digest('hex');

    const sigClean = signatureHeader.replace(/^sha256=/i, '').trim();
    const a = Buffer.from(sigClean, 'utf8');
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
    if (event === 'DEPOSIT_PIX_CONFIRMED') {
      newStatus = 'PIX_CONFIRMED';
    } else if (event === 'DEPOSIT_ASSET_SUCCESS') {
      newStatus = 'SETTLED_CRYPTO';
    } else if (event === 'DEPOSIT_ASSET_FAILED') {
      newStatus = 'FAILED';
    } else if (event === 'DEPOSIT_EXPIRED') {
      newStatus = 'EXPIRED';
    }

    if (!newStatus) return null;

    return {
      provider: 'hodle',
      providerChargeId: data.id ? String(data.id) : undefined,
      externalId: data.externalId ? String(data.externalId) : undefined,
      newStatus,
      txHash: data.txHash ? String(data.txHash) : undefined,
      endToEndId: data.endToEndId ? String(data.endToEndId) : undefined,
      cryptoAmount: data.amount != null ? Number(data.amount) : undefined,
      rawEventName: event,
    };
  }
}
