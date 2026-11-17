import crypto from 'node:crypto';
import QRCode from 'qrcode';
import type {
  ChargePollResult,
  CreateChargeInput,
  CreateChargeOutput,
  IPixCryptoProvider,
  OrderStatus,
  WebhookSettlementEvent,
} from '../types/domain.ts';
import {
  safeOptionalId,
  safePositiveNumber,
  safePrimitiveString,
  stripTrailingSlashes,
} from '../utils/cpfCnpjValidator.ts';

const FETCH_TIMEOUT_MS = 15_000;

export class NoxPayProvider implements IPixCryptoProvider {
  public readonly name = 'noxpay' as const;
  public readonly minAmountBrl = 10;
  public readonly maxAmountBrl = 50_000;
  private readonly config: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
  };

  constructor(config: { apiUrl: string; apiKey: string; webhookSecret: string }) {
    this.config = {
      apiUrl: stripTrailingSlashes(config.apiUrl),
      apiKey: config.apiKey.trim(),
      webhookSecret: config.webhookSecret.trim(),
    };
  }

  public async createCharge(input: CreateChargeInput): Promise<CreateChargeOutput> {
    if (!this.config.apiKey) {
      throw new Error('API_KEY_MISSING: Cole sua Chave de API da NoxPay no Passo 1 do painel.');
    }
    if (!input.walletAddress) {
      throw new Error('WALLET_MISSING: Informe o endereço da sua carteira cripto no Passo 1.');
    }

    const bodyPayload: Record<string, unknown> = {
      currency_code: 'BRL_PIX',
      amount_fiat: input.amountBrl,
      crypto_currency: input.cryptoAsset.toUpperCase(),
      crypto_network: input.cryptoNetwork.toUpperCase(),
      wallet_address: input.walletAddress,
      external_id: input.externalId,
    };
    if (input.webhookUrl.startsWith('https://') && !input.webhookUrl.includes('localhost')) {
      bodyPayload.webhook = input.webhookUrl;
    }

    const response = await fetch(`${this.config.apiUrl}/crossramp_checkout`, {
      method: 'POST',
      headers: {
        'api-key': this.config.apiKey,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(bodyPayload),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`NoxPay (HTTP ${response.status}): ${errorText}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    const pixCopyPaste = (
      safeOptionalId(data.pix_code) ??
      safeOptionalId(data.qr_code_text) ??
      safeOptionalId(data.brcode) ??
      safeOptionalId(data.checkout_url) ??
      ''
    ).trim();
    if (!pixCopyPaste) {
      throw new Error('A resposta da NoxPay não retornou código Pix nem link de checkout.');
    }

    const expiresAt =
      safeOptionalId(data.expires_at) ??
      new Date(Date.now() + input.expirationMinutes * 60_000).toISOString();

    const pixQrCodeBase64 = await QRCode.toDataURL(pixCopyPaste, { width: 320, margin: 2 });

    return {
      providerChargeId: safeOptionalId(data.txid) ?? safeOptionalId(data.id) ?? input.externalId,
      pixCopyPaste,
      pixQrCodeBase64,
      paymentUrl: safeOptionalId(data.checkout_url),
      estimatedCryptoAmount: safePositiveNumber(data.amount_crypto),
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
    const statusRaw = safePrimitiveString(obj.status).toUpperCase();

    let newStatus: OrderStatus | null = null;
    if (statusRaw === 'PAID' || statusRaw === 'PIX_PAID') {
      newStatus = 'PIX_CONFIRMED';
    } else if (statusRaw === 'COMPLETED' || statusRaw === 'SETTLED') {
      newStatus = 'SETTLED_CRYPTO';
    } else if (statusRaw === 'EXPIRED') {
      newStatus = 'EXPIRED';
    } else if (statusRaw === 'FAILED' || statusRaw === 'REFUNDED' || statusRaw === 'CANCELLED') {
      newStatus = 'FAILED';
    }

    if (!newStatus) return null;

    return {
      provider: 'noxpay',
      eventId: safeOptionalId(obj.event_id),
      providerChargeId: safeOptionalId(obj.txid) ?? safeOptionalId(obj.id),
      externalId: safeOptionalId(obj.external_id),
      newStatus,
      txHash: safeOptionalId(obj.tx_hash),
      cryptoAmount: safePositiveNumber(obj.amount_crypto),
      rawEventName: statusRaw,
    };
  }

  public async checkChargeStatus(providerChargeId: string): Promise<ChargePollResult | null> {
    if (!this.config.apiKey || !providerChargeId) return null;
    try {
      const res = await fetch(
        `${this.config.apiUrl}/crossramp_checkout/${encodeURIComponent(providerChargeId)}`,
        {
          headers: {
            'api-key': this.config.apiKey,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        }
      );
      if (res.status === 404) return { status: 'EXPIRED' };
      if (!res.ok) return null;
      const obj = (await res.json()) as Record<string, unknown>;
      const st = safePrimitiveString(obj.status).toUpperCase();
      if (st === 'COMPLETED' || st === 'SETTLED') {
        return {
          status: 'SETTLED_CRYPTO',
          txHash: safeOptionalId(obj.tx_hash),
          cryptoAmount: safePositiveNumber(obj.amount_crypto),
        };
      }
      if (st === 'PAID' || st === 'PIX_PAID') {
        return { status: 'PIX_CONFIRMED' };
      }
      if (st === 'FAILED' || st === 'REFUNDED' || st === 'CANCELLED') {
        return { status: 'FAILED' };
      }
      if (st === 'EXPIRED') {
        return { status: 'EXPIRED' };
      }
      return { status: 'PENDING' };
    } catch {
      return null;
    }
  }
}
