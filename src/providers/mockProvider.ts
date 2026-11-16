import crypto from 'node:crypto';
import QRCode from 'qrcode';
import type {
  ChargePollResult,
  CreateChargeInput,
  CreateChargeOutput,
  IPixCryptoProvider,
  WebhookSettlementEvent,
} from '../types/domain.ts';

export class MockProvider implements IPixCryptoProvider {
  public readonly name = 'mock' as const;
  public readonly minAmountBrl = 1;
  public readonly maxAmountBrl = 50_000;
  private readonly webhookSecret: string;

  constructor(options: { webhookSecret?: string } = {}) {
    // Segredo aleatório por boot quando não especificado, bloqueando webhooks falsificados externos!
    this.webhookSecret = options.webhookSecret || crypto.randomBytes(24).toString('hex');
  }

  public async createCharge(input: CreateChargeInput): Promise<CreateChargeOutput> {
    const providerChargeId = `mock_${crypto.randomBytes(6).toString('hex')}`;
    const expiresAt = new Date(Date.now() + input.expirationMinutes * 60_000).toISOString();

    let estimatedCryptoAmount: number;
    if (input.cryptoAsset.toUpperCase() === 'DEPIX') {
      estimatedCryptoAmount = Math.max(0, Math.round((input.amountBrl * 0.98 - 0.99) * 100) / 100);
    } else if (input.cryptoAsset.toUpperCase() === 'BTC') {
      estimatedCryptoAmount = Number(((input.amountBrl * 0.99) / 520_000).toFixed(8));
    } else {
      estimatedCryptoAmount = Math.round(((input.amountBrl * 0.99) / 5.75) * 100) / 100;
    }

    const amountFixed = input.amountBrl.toFixed(2);
    const pixCopyPaste =
      `00020126580014br.gov.bcb.pix0136${crypto.randomUUID()}` +
      `52040000530398654${String(amountFixed.length).padStart(2, '0')}${amountFixed}` +
      `5802BR5915MODO_TESTE_DEMO6009SAO_PAULO62140510${providerChargeId.slice(-10)}6304ABCD`;

    const pixQrCodeBase64 = await QRCode.toDataURL(pixCopyPaste, {
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 320,
    });

    return {
      providerChargeId,
      pixCopyPaste,
      pixQrCodeBase64,
      estimatedCryptoAmount,
      expiresAt,
    };
  }

  public signPayload(rawBody: string): string {
    return crypto.createHmac('sha256', this.webhookSecret).update(rawBody).digest('hex');
  }

  public verifyWebhookSignature(
    rawBody: string,
    headers: Record<string, string | string[] | undefined>
  ): boolean {
    const signature = headers['x-mock-signature'];
    if (!signature || typeof signature !== 'string' || !this.webhookSecret) return false;
    const expected = this.signPayload(rawBody);
    const sigBuf = Buffer.from(signature, 'utf8');
    const expBuf = Buffer.from(expected, 'utf8');
    if (sigBuf.length !== expBuf.length) return false;
    return crypto.timingSafeEqual(sigBuf, expBuf);
  }

  public parseWebhookPayload(payload: unknown): WebhookSettlementEvent | null {
    if (!payload || typeof payload !== 'object') return null;
    const obj = payload as Record<string, unknown>;
    const event = String(obj.event || '');
    const data = (obj.data || {}) as Record<string, unknown>;

    if (event === 'MOCK_SETTLED_CRYPTO') {
      return {
        provider: 'mock',
        eventId: obj.eventId ? String(obj.eventId) : undefined,
        providerChargeId: data.providerChargeId ? String(data.providerChargeId) : undefined,
        externalId: data.externalId ? String(data.externalId) : undefined,
        newStatus: 'SETTLED_CRYPTO',
        txHash: data.txHash ? String(data.txHash) : `0x${crypto.randomBytes(32).toString('hex')}`,
        endToEndId: data.endToEndId
          ? String(data.endToEndId)
          : `E00000000${Date.now()}MOCK`,
        cryptoAmount: data.cryptoAmount != null ? Number(data.cryptoAmount) : undefined,
        rawEventName: event,
      };
    }

    return null;
  }

  public async checkChargeStatus(_providerChargeId: string): Promise<ChargePollResult | null> {
    return null;
  }
}
