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

export class HodleProvider implements IPixCryptoProvider {
  public readonly name = 'hodle' as const;
  public readonly minAmountBrl = 5;
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
      throw new Error('API_KEY_MISSING: Cole sua Chave de API da Hodle no Passo 1 do painel.');
    }
    if (!input.walletAddress) {
      throw new Error('WALLET_MISSING: Informe o endereço da sua carteira cripto no Passo 1.');
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
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        }
      );
      if (quoteRes.ok) {
        const quoteData = (await quoteRes.json()) as Record<string, unknown>;
        estimatedCryptoAmount =
          safePositiveNumber(quoteData.estimatedAmount) ?? safePositiveNumber(quoteData.amountOut);
      }
    } catch {
      // Cotação prévia opcional
    }

    const bodyPayload: Record<string, unknown> = {
      externalId: input.externalId,
      amount: input.amountBrl.toFixed(2),
      asset: input.cryptoAsset.toUpperCase(),
      network: input.cryptoNetwork.toUpperCase(),
      destinationAddress: input.walletAddress,
      expirationMinutes: input.expirationMinutes,
    };
    if (input.webhookUrl.startsWith('https://') && !input.webhookUrl.includes('localhost')) {
      bodyPayload.webhookUrl = input.webhookUrl;
    }

    const response = await fetch(`${this.config.apiUrl}/api/deposit/asset`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(bodyPayload),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Hodle (HTTP ${response.status}): ${errorText}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    const pixCopyPaste = (
      safeOptionalId(data.pixCopyPaste) ??
      safeOptionalId(data.qrCode) ??
      safeOptionalId(data.brcode) ??
      ''
    ).trim();
    if (!pixCopyPaste) {
      throw new Error('Resposta da API Hodle não retornou o código Pix Copia e Cola.');
    }

    const expiresAt =
      safeOptionalId(data.expiresAt) ??
      new Date(Date.now() + input.expirationMinutes * 60_000).toISOString();

    const pixQrCodeBase64 =
      safeOptionalId(data.qrCodeBase64) ??
      (await QRCode.toDataURL(pixCopyPaste, { width: 320, margin: 2 }));

    return {
      providerChargeId:
        safeOptionalId(data.id) ?? safeOptionalId(data.depositId) ?? input.externalId,
      pixCopyPaste,
      pixQrCodeBase64,
      estimatedCryptoAmount: safePositiveNumber(data.assetAmount) ?? estimatedCryptoAmount,
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

    const sigClean = signatureHeader.replace(/^sha256=/i, '').trim().toLowerCase();
    const a = Buffer.from(sigClean, 'utf8');
    const b = Buffer.from(expectedHex.toLowerCase(), 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  public parseWebhookPayload(payload: unknown): WebhookSettlementEvent | null {
    if (!payload || typeof payload !== 'object') return null;
    const root = payload as Record<string, unknown>;
    const event = safePrimitiveString(root.event);
    const data = (typeof root.data === 'object' && root.data ? root.data : {}) as Record<
      string,
      unknown
    >;

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
      eventId: safeOptionalId(root.eventId),
      providerChargeId: safeOptionalId(data.id),
      externalId: safeOptionalId(data.externalId),
      newStatus,
      txHash: safeOptionalId(data.txHash),
      endToEndId: safeOptionalId(data.endToEndId),
      cryptoAmount: safePositiveNumber(data.amount),
      rawEventName: event,
    };
  }

  public async checkChargeStatus(providerChargeId: string): Promise<ChargePollResult | null> {
    if (!this.config.apiKey || !providerChargeId) return null;
    try {
      const res = await fetch(
        `${this.config.apiUrl}/api/deposit/${encodeURIComponent(providerChargeId)}`,
        {
          headers: {
            Authorization: `Bearer ${this.config.apiKey}`,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        }
      );
      if (res.status === 404) return { status: 'EXPIRED' };
      if (!res.ok) return null;
      const data = (await res.json()) as Record<string, unknown>;
      const st = safePrimitiveString(data.status).toUpperCase();
      if (st === 'COMPLETED' || st === 'ASSET_SUCCESS' || st === 'SETTLED') {
        return {
          status: 'SETTLED_CRYPTO',
          txHash: safeOptionalId(data.txHash),
          cryptoAmount: safePositiveNumber(data.assetAmount),
        };
      }
      if (st === 'PIX_CONFIRMED' || st === 'PAID' || st === 'PROCESSING') {
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
