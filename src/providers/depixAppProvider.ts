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

const FETCH_TIMEOUT_MS = 15_000;
const WEBHOOK_TOLERANCE_SECONDS = 300; // 5 minutos contra replay attacks

export class DePixAppProvider implements IPixCryptoProvider {
  public readonly name = 'depixapp' as const;
  public readonly minAmountBrl = 5;
  public readonly maxAmountBrl = 6_000;
  private readonly config: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
    skipTimestampWindowCheck?: boolean;
  };

  constructor(config: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
    skipTimestampWindowCheck?: boolean;
  }) {
    const cleanBase = config.apiUrl.replace(/\/+$/, '');
    this.config = {
      apiUrl: cleanBase.endsWith('/api') ? cleanBase : `${cleanBase}/api`,
      apiKey: config.apiKey.trim(),
      webhookSecret: config.webhookSecret.trim(),
      skipTimestampWindowCheck: config.skipTimestampWindowCheck,
    };
  }

  public isTestKey(): boolean {
    return this.config.apiKey.startsWith('sk_test_');
  }

  /**
   * Fail-closed conforme `depix_docs.md:1715`: bloqueia eventos `is_live: false | 0`
   * sempre que a chave NÃO for explicitamente uma chave sandbox `sk_test_`.
   */
  private shouldRejectSandboxItem(isLiveField: unknown): boolean {
    if (this.isTestKey()) return false;
    return isLiveField === false || isLiveField === 0;
  }

  public async createCharge(input: CreateChargeInput): Promise<CreateChargeOutput> {
    if (!this.config.apiKey) {
      throw new Error(
        'API_KEY_MISSING: Cole sua Chave de API da DePix App (sk_test_... ou sk_live_...) no Passo 1 do painel.'
      );
    }

    const amountInCents = Math.round(input.amountBrl * 100);
    if (amountInCents < 500) {
      throw new Error('MIN_AMOUNT: O valor mínimo na DePix App é de R$ 5,00.');
    }
    if (amountInCents > 600_000) {
      throw new Error('MAX_AMOUNT: O valor máximo por cobrança na DePix App é de R$ 6.000,00.');
    }

    const expMinutes = Number.isFinite(input.expirationMinutes) ? input.expirationMinutes : 15;
    const expiresInSeconds = Math.min(1200, Math.max(300, Math.round(expMinutes * 60)));
    const publicHttpsCallback =
      input.webhookUrl.startsWith('https://') && !input.webhookUrl.includes('localhost')
        ? input.webhookUrl
        : undefined;

    const estimatedNet = Math.max(0, Math.round((input.amountBrl * 0.98 - 0.99) * 100) / 100);

    const saoPauloToday = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Sao_Paulo',
    }).format(new Date());

    const uniqueSlug = `chg-${Date.now().toString(36)}-${crypto.randomBytes(5).toString('hex')}`;

    const chargePayload: Record<string, unknown> = {
      name: `Pix ${uniqueSlug.slice(-8).toUpperCase()}`,
      slug: uniqueSlug,
      amount: amountInCents,
      kind: 'charge',
      due_date: saoPauloToday,
      expires_in: expiresInSeconds,
      description: `Cobrança automática #${input.externalId}`,
      metadata: {
        external_id: input.externalId,
      },
    };
    if (publicHttpsCallback) {
      chargePayload.callback_url = publicHttpsCallback;
    }

    const response = await fetch(`${this.config.apiUrl}/products`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(chargePayload),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    if (!response.ok) {
      const errBody = await response.text();
      throw new Error(this.extractHumanError(response.status, errBody));
    }

    const data = (await response.json()) as Record<string, unknown>;
    const product =
      typeof data.product === 'object' && data.product
        ? (data.product as Record<string, unknown>)
        : data;
    const prdId = String(product.id ?? '');
    const paymentUrl = String(
      product.payment_url ?? (prdId ? `https://pay.depixapp.com/c/${prdId}` : '')
    );

    if (!prdId || !paymentUrl) {
      throw new Error('Resposta da DePix App não retornou o link privado da cobrança.');
    }

    const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();
    const pixQrCodeBase64 = await QRCode.toDataURL(paymentUrl, { width: 320, margin: 2 });

    return {
      providerChargeId: prdId,
      pixCopyPaste: paymentUrl,
      pixQrCodeBase64,
      paymentUrl,
      estimatedCryptoAmount: estimatedNet,
      expiresAt,
    };
  }

  public verifyWebhookSignature(
    rawBody: string,
    headers: Record<string, string | string[] | undefined>
  ): boolean {
    const sig = headers['x-depix-signature'];
    if (!sig || typeof sig !== 'string' || !this.config.webhookSecret) {
      return false;
    }

    const parts = sig.split(',').map((p) => p.trim());
    const tPart = parts.find((p) => p.startsWith('t='));
    const v1Part = parts.find((p) => p.startsWith('v1='));
    if (!tPart || !v1Part) {
      return false;
    }

    const timestamp = tPart.slice(2);
    const receivedV1 = v1Part.slice(3);
    if (!/^\d+$/.test(timestamp) || !/^[0-9a-f]{64}$/i.test(receivedV1)) {
      return false;
    }

    if (!this.config.skipTimestampWindowCheck) {
      const tsSeconds = Number(timestamp);
      const nowSeconds = Math.floor(Date.now() / 1000);
      if (Math.abs(nowSeconds - tsSeconds) > WEBHOOK_TOLERANCE_SECONDS) {
        return false;
      }
    }

    const expectedHex = crypto
      .createHmac('sha256', this.config.webhookSecret)
      .update(`${timestamp}.${rawBody}`)
      .digest('hex');

    const a = Buffer.from(receivedV1.toLowerCase(), 'utf8');
    const b = Buffer.from(expectedHex.toLowerCase(), 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  public parseWebhookPayload(payload: unknown): WebhookSettlementEvent | null {
    if (!payload || typeof payload !== 'object') return null;
    const root = payload as Record<string, unknown>;
    const eventName = String(root.event ?? '').toLowerCase();
    const data = (typeof root.data === 'object' && root.data ? root.data : root) as Record<
      string,
      unknown
    >;

    if (this.shouldRejectSandboxItem(data.is_live)) {
      return null;
    }

    const rawStatus = String(data.status ?? eventName).toLowerCase();
    let newStatus: OrderStatus | null = null;

    if (
      rawStatus === 'completed' ||
      rawStatus === 'depix_sent' ||
      eventName === 'checkout.completed' ||
      eventName === 'deposit.depix_sent'
    ) {
      newStatus = 'SETTLED_CRYPTO';
    } else if (
      rawStatus === 'processing' ||
      rawStatus === 'approved' ||
      eventName === 'checkout.processing' ||
      eventName === 'checkout.approved'
    ) {
      newStatus = 'PIX_CONFIRMED';
    } else if (rawStatus === 'expired' || eventName === 'checkout.expired') {
      newStatus = 'EXPIRED';
    } else if (
      rawStatus === 'cancelled' ||
      rawStatus === 'canceled' ||
      rawStatus === 'refunded' ||
      rawStatus === 'failed' ||
      eventName === 'checkout.cancelled'
    ) {
      newStatus = 'FAILED';
    }

    if (!newStatus) return null;

    let metadata: Record<string, unknown> = {};
    if (typeof data.metadata === 'string') {
      try {
        metadata = JSON.parse(data.metadata) as Record<string, unknown>;
      } catch {
        metadata = {};
      }
    } else if (typeof data.metadata === 'object' && data.metadata) {
      metadata = data.metadata as Record<string, unknown>;
    }

    const chargeId = data.product_id
      ? String(data.product_id)
      : data.id
        ? String(data.id)
        : undefined;

    return {
      provider: 'depixapp',
      eventId: data.event_id ? String(data.event_id) : undefined,
      providerChargeId: chargeId,
      externalId: metadata.external_id
        ? String(metadata.external_id)
        : data.external_id
          ? String(data.external_id)
          : undefined,
      newStatus,
      txHash: data.blockchain_tx_id
        ? String(data.blockchain_tx_id)
        : data.tx_hash
          ? String(data.tx_hash)
          : data.txid
            ? String(data.txid)
            : undefined,
      cryptoAmount:
        data.amount_received != null
          ? Number(data.amount_received) / 100
          : data.net_amount != null
            ? Number(data.net_amount) / 100
            : undefined,
      rawEventName: eventName || rawStatus,
    };
  }

  public async checkChargeStatus(providerChargeId: string): Promise<ChargePollResult | null> {
    if (!this.config.apiKey || !providerChargeId) return null;

    try {
      if (providerChargeId.startsWith('prd_')) {
        const res = await fetch(
          `${this.config.apiUrl}/products/${encodeURIComponent(providerChargeId)}/checkouts?limit=100`,
          {
            headers: {
              Authorization: `Bearer ${this.config.apiKey}`,
              Accept: 'application/json',
            },
            signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
          }
        );
        if (!res.ok) return null;
        const root = (await res.json()) as Record<string, unknown>;
        const rawList = Array.isArray(root.checkouts)
          ? (root.checkouts as Array<Record<string, unknown>>)
          : [];

        const validItems = rawList.filter((item) => !this.shouldRejectSandboxItem(item.is_live));
        if (validItems.length === 0) return null;

        // 1ª prioridade: `completed`
        const completedItem = validItems.find(
          (item) => String(item.status ?? '').toLowerCase() === 'completed'
        );
        if (completedItem) {
          let txHash = completedItem.blockchain_tx_id
            ? String(completedItem.blockchain_tx_id)
            : undefined;
          if (!txHash && completedItem.id) {
            txHash = await this.fetchCheckoutBlockchainTxId(String(completedItem.id));
          }
          return { status: 'SETTLED_CRYPTO', txHash };
        }

        // 2ª prioridade: `processing` | `approved`
        const processingItem = validItems.find((item) => {
          const st = String(item.status ?? '').toLowerCase();
          return st === 'processing' || st === 'approved';
        });
        if (processingItem) {
          return { status: 'PIX_CONFIRMED' };
        }

        // 3ª prioridade: `pending` ainda válido
        const nowMs = Date.now();
        const activePending = validItems.find((item) => {
          if (String(item.status ?? '').toLowerCase() !== 'pending') return false;
          if (!item.expires_at) return false;
          return new Date(String(item.expires_at)).getTime() > nowMs;
        });
        if (activePending && activePending.expires_at) {
          return {
            status: 'PENDING',
            activePendingExpiresAt: String(activePending.expires_at),
          };
        }

        // 4ª prioridade: checkout estornado/cancelado (ex: PAYER_MISMATCH após ter passado por processing!)
        const cancelledItem = validItems.find((item) => {
          const st = String(item.status ?? '').toLowerCase();
          return st === 'cancelled' || st === 'canceled' || st === 'refunded' || st === 'failed';
        });
        if (cancelledItem) {
          const reasons = Array.isArray(cancelledItem.rejection_reasons)
            ? cancelledItem.rejection_reasons.map(String)
            : undefined;
          return { status: 'FAILED', rejectionReasons: reasons };
        }

        return null;
      }

      const res = await fetch(
        `${this.config.apiUrl}/checkouts/${encodeURIComponent(providerChargeId)}`,
        {
          headers: {
            Authorization: `Bearer ${this.config.apiKey}`,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        }
      );
      if (!res.ok) return null;
      const root = (await res.json()) as Record<string, unknown>;
      const chk =
        typeof root.checkout === 'object' && root.checkout
          ? (root.checkout as Record<string, unknown>)
          : root;

      if (this.shouldRejectSandboxItem(chk.is_live)) {
        return null;
      }

      const rawStatus = String(chk.status ?? '').toLowerCase();
      if (rawStatus === 'completed') {
        return {
          status: 'SETTLED_CRYPTO',
          txHash: chk.blockchain_tx_id ? String(chk.blockchain_tx_id) : undefined,
        };
      }
      if (rawStatus === 'processing' || rawStatus === 'approved') {
        return { status: 'PIX_CONFIRMED' };
      }
      if (rawStatus === 'expired') {
        return { status: 'EXPIRED' };
      }
      if (rawStatus === 'cancelled' || rawStatus === 'failed' || rawStatus === 'refunded') {
        const reasons = Array.isArray(chk.rejection_reasons)
          ? chk.rejection_reasons.map(String)
          : undefined;
        return { status: 'FAILED', rejectionReasons: reasons };
      }
      return null;
    } catch {
      return null;
    }
  }

  public async expireCharge(providerChargeId: string): Promise<void> {
    if (!this.config.apiKey || !providerChargeId.startsWith('prd_')) return;
    try {
      await fetch(
        `${this.config.apiUrl}/products/${encodeURIComponent(providerChargeId)}/deactivate`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${this.config.apiKey}`,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        }
      );
    } catch {
      // Silencioso
    }
  }

  private async fetchCheckoutBlockchainTxId(checkoutId: string): Promise<string | undefined> {
    try {
      const res = await fetch(
        `${this.config.apiUrl}/checkouts/${encodeURIComponent(checkoutId)}`,
        {
          headers: {
            Authorization: `Bearer ${this.config.apiKey}`,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        }
      );
      if (!res.ok) return undefined;
      const root = (await res.json()) as Record<string, unknown>;
      const chk =
        typeof root.checkout === 'object' && root.checkout
          ? (root.checkout as Record<string, unknown>)
          : root;
      return chk.blockchain_tx_id ? String(chk.blockchain_tx_id) : undefined;
    } catch {
      return undefined;
    }
  }

  private extractHumanError(status: number, rawText: string): string {
    try {
      const parsed = JSON.parse(rawText) as Record<string, unknown>;
      const legacy =
        typeof parsed.response === 'object' && parsed.response
          ? (parsed.response as Record<string, unknown>).errorMessage
          : undefined;
      const errObj =
        typeof parsed.error === 'object' && parsed.error
          ? (parsed.error as Record<string, unknown>)
          : undefined;
      const code = errObj?.code ? String(errObj.code) : '';
      const msg = legacy ? String(legacy) : errObj?.message ? String(errObj.message) : rawText;
      return `DePix App (${status}${code ? ' ' + code : ''}): ${msg}`;
    } catch {
      return `DePix App (HTTP ${status}): ${rawText}`;
    }
  }
}
