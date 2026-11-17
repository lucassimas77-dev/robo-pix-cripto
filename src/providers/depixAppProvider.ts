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
  asPlainObject,
  safeOptionalId,
  safePositiveNumber,
  safePrimitiveString,
  stripTrailingSlashes,
} from '../utils/cpfCnpjValidator.ts';

const FETCH_TIMEOUT_MS = 15_000;
const WEBHOOK_TOLERANCE_SECONDS = 300; // 5 minutos contra replay attacks
const DEPIX_RAIL_GRACE_MS = 15 * 60_000; // Janela de graça oficial de 15 min do rail Liquid (depix_docs.md:1223)
const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_INTERACTIVE_REQ_PER_MIN = 28; // Estritamente abaixo do limite de 30 req/min por lojista da DePix App
const MAX_BACKGROUND_REQ_PER_MIN = 20; // Reserva margem garantida para novas cobranças no WhatsApp
const MAX_TRACKED_API_KEYS = 100;

export class DePixAppProvider implements IPixCryptoProvider {
  private static readonly requestWindows = new Map<string, number[]>();

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
    const cleanBase = stripTrailingSlashes(config.apiUrl);
    this.config = {
      apiUrl: cleanBase.endsWith('/api') ? cleanBase : `${cleanBase}/api`,
      apiKey: config.apiKey.trim(),
      webhookSecret: config.webhookSecret.trim(),
      skipTimestampWindowCheck: config.skipTimestampWindowCheck,
    };
  }

  public static clearRateLimitWindows(): void {
    DePixAppProvider.requestWindows.clear();
  }

  private tryAcquireRateSlot(priority: 'interactive' | 'background'): boolean {
    const bucketKey = this.config.apiKey || '__default__';
    const now = Date.now();
    const cutoff = now - RATE_LIMIT_WINDOW_MS;

    const existing = DePixAppProvider.requestWindows.get(bucketKey) ?? [];
    const active = existing.filter((ts) => ts > cutoff);

    const cap =
      priority === 'interactive' ? MAX_INTERACTIVE_REQ_PER_MIN : MAX_BACKGROUND_REQ_PER_MIN;
    if (active.length >= cap) {
      DePixAppProvider.requestWindows.set(bucketKey, active);
      return false;
    }

    active.push(now);
    if (
      !DePixAppProvider.requestWindows.has(bucketKey) &&
      DePixAppProvider.requestWindows.size >= MAX_TRACKED_API_KEYS
    ) {
      const oldestKey = DePixAppProvider.requestWindows.keys().next().value;
      if (oldestKey !== undefined) {
        DePixAppProvider.requestWindows.delete(oldestKey);
      }
    }
    DePixAppProvider.requestWindows.set(bucketKey, active);
    return true;
  }

  public isTestKey(): boolean {
    return this.config.apiKey.startsWith('sk_test_');
  }

  /**
   * Whitelist estrita fail-closed conforme `depix_docs.md:1715`:
   * Em produção (`!isTestKey()`), todo checkout exige `is_live === true || is_live === 1`.
   * Eventos `deposit.*` (que não existem em sandbox e omitem `is_live`, conf. `depix_docs.md:1744`)
   * só são bloqueados se trouxerem flag explicitamente falsa.
   */
  private shouldRejectSandboxItem(isLiveField: unknown, isDepositEvent = false): boolean {
    if (this.isTestKey()) return false;
    if (isDepositEvent) {
      return (
        isLiveField === false ||
        isLiveField === 0 ||
        isLiveField === 'false' ||
        isLiveField === '0'
      );
    }
    return !(isLiveField === true || isLiveField === 1);
  }

  private extractCryptoAmountFromItem(item: Record<string, unknown>): number | undefined {
    const depixBlock =
      typeof item.depix === 'object' && item.depix
        ? (item.depix as Record<string, unknown>)
        : undefined;

    const dueCents = safePositiveNumber(item.depix_due_cents);
    if (dueCents !== undefined) return dueCents / 100;

    const depixCents = safePositiveNumber(depixBlock?.amount_cents);
    if (depixCents !== undefined) return depixCents / 100;

    const receivedCents = safePositiveNumber(item.amount_received);
    if (receivedCents !== undefined) return receivedCents / 100;

    const netCents = safePositiveNumber(item.net_amount);
    if (netCents !== undefined) return netCents / 100;

    return undefined;
  }

  private computeEffectivePendingExpiresMs(item: Record<string, unknown>): number {
    const expStr = safePrimitiveString(item.expires_at);
    if (!expStr) return 0;
    const baseMs = new Date(expStr).getTime();
    if (!Number.isFinite(baseMs)) return 0;
    const isDepixRail =
      safePrimitiveString(item.payment_method).toLowerCase() === 'depix' ||
      Boolean(item.depix && typeof item.depix === 'object');
    return baseMs + (isDepixRail ? DEPIX_RAIL_GRACE_MS : 0);
  }

  public async createCharge(input: CreateChargeInput): Promise<CreateChargeOutput> {
    if (!this.config.apiKey) {
      throw new Error(
        'API_KEY_MISSING: Cole sua Chave de API da DePix App (sk_test_... ou sk_live_...) no Passo 1 do painel.'
      );
    }

    if (!Number.isFinite(input.amountBrl) || input.amountBrl <= 0) {
      throw new Error('INVALID_AMOUNT: Valor inválido para cobrança Pix.');
    }

    const amountInCents = Math.round(input.amountBrl * 100);
    if (!Number.isFinite(amountInCents) || amountInCents < 500) {
      throw new Error('MIN_AMOUNT: O valor mínimo na DePix App é de R$ 5,00.');
    }
    if (amountInCents > 600_000) {
      throw new Error('MAX_AMOUNT: O valor máximo por cobrança na DePix App é de R$ 6.000,00.');
    }

    if (!this.tryAcquireRateSlot('interactive')) {
      throw new Error(
        'RATE_LIMITED: Limite de segurança de requisições por minuto atingido. Aguarde alguns segundos e tente novamente.'
      );
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

    const data = asPlainObject(await response.json());
    if (!data) {
      throw new Error('Resposta inválida da DePix App ao criar cobrança.');
    }
    const product = asPlainObject(data.product) ?? data;
    const prdId = safePrimitiveString(product.id).trim();
    const paymentUrl =
      safePrimitiveString(product.payment_url).trim() ||
      (prdId ? `https://pay.depixapp.com/c/${prdId}` : '');

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
    const root = asPlainObject(payload);
    if (!root) return null;
    const eventName = safePrimitiveString(root.event).toLowerCase();
    const data = asPlainObject(root.data) ?? root;

    const isDepositEvent =
      eventName.startsWith('deposit.') ||
      safePrimitiveString(data.type).toLowerCase() === 'deposit';

    if (this.shouldRejectSandboxItem(data.is_live, isDepositEvent)) {
      return null;
    }

    const rawStatus = (safePrimitiveString(data.status) || eventName).toLowerCase();
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
    } else if (
      (rawStatus === 'expired' || eventName === 'checkout.expired') &&
      !safeOptionalId(data.product_id)
    ) {
      // Ignora `checkout.expired` de sub-checkout individual quando há `product_id` (`prd_...`),
      // pois um 2º QR pode estar ativo no mesmo link; o `ExpirationWatcher` controla o vencimento de `prd_...`.
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
        const parsedMeta = JSON.parse(data.metadata) as unknown;
        if (parsedMeta && typeof parsedMeta === 'object' && !Array.isArray(parsedMeta)) {
          metadata = parsedMeta as Record<string, unknown>;
        }
      } catch {
        metadata = {};
      }
    } else if (typeof data.metadata === 'object' && data.metadata && !Array.isArray(data.metadata)) {
      metadata = data.metadata as Record<string, unknown>;
    }

    const chargeId = safeOptionalId(data.product_id) ?? safeOptionalId(data.id);

    return {
      provider: 'depixapp',
      eventId: safeOptionalId(data.event_id),
      providerChargeId: chargeId,
      externalId: safeOptionalId(metadata.external_id) ?? safeOptionalId(data.external_id),
      newStatus,
      txHash:
        safeOptionalId(data.blockchain_tx_id) ??
        safeOptionalId(data.tx_hash) ??
        safeOptionalId(data.txid),
      cryptoAmount: this.extractCryptoAmountFromItem(data),
      rawEventName: eventName || rawStatus,
    };
  }

  /**
   * Retorna `null` APENAS em falhas transitórias/rede/rate-limit/credenciais (nunca expira às cegas!).
   * Quando a API responde HTTP 200 sem pagamentos ainda, retorna `{ status: 'PENDING' }`.
   */
  public async checkChargeStatus(providerChargeId: string): Promise<ChargePollResult | null> {
    if (!this.config.apiKey || !providerChargeId) return null;
    if (!this.tryAcquireRateSlot('background')) return null;

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
        if (res.status === 404) return { status: 'EXPIRED' };
        if (!res.ok) return null;

        const root = asPlainObject(await res.json());
        if (!root) return null;
        const rawList = Array.isArray(root.checkouts) ? (root.checkouts as unknown[]) : [];

        const validItems = rawList
          .map((entry) => asPlainObject(entry))
          .filter(
            (item): item is Record<string, unknown> =>
              item !== null && !this.shouldRejectSandboxItem(item.is_live, false)
          );
        if (validItems.length === 0) {
          return { status: 'PENDING' };
        }

        // 1ª prioridade: `completed`
        const completedItem = validItems.find(
          (item) => safePrimitiveString(item.status).toLowerCase() === 'completed'
        );
        if (completedItem) {
          let txHash = safeOptionalId(completedItem.blockchain_tx_id);
          let cryptoAmount = this.extractCryptoAmountFromItem(completedItem);
          const completedId = safeOptionalId(completedItem.id);

          if ((!txHash || cryptoAmount === undefined) && completedId) {
            const details = await this.fetchCheckoutSettlementDetails(completedId);
            if (!txHash && details.txHash) txHash = details.txHash;
            if (cryptoAmount === undefined && details.cryptoAmount !== undefined) {
              cryptoAmount = details.cryptoAmount;
            }
          }
          return { status: 'SETTLED_CRYPTO', txHash, cryptoAmount };
        }

        // 2ª prioridade: `processing` | `approved`
        const processingItem = validItems.find((item) => {
          const st = safePrimitiveString(item.status).toLowerCase();
          return st === 'processing' || st === 'approved';
        });
        if (processingItem) {
          return { status: 'PIX_CONFIRMED' };
        }

        // 3ª prioridade: `pending` ainda válido (respeitando a grace window de 15 min no rail `depix`)
        const nowMs = Date.now();
        let latestPendingExpMs = 0;
        for (const item of validItems) {
          if (safePrimitiveString(item.status).toLowerCase() !== 'pending') continue;
          const effMs = this.computeEffectivePendingExpiresMs(item);
          if (effMs > nowMs && effMs > latestPendingExpMs) {
            latestPendingExpMs = effMs;
          }
        }
        if (latestPendingExpMs > nowMs) {
          return {
            status: 'PENDING',
            activePendingExpiresAt: new Date(latestPendingExpMs).toISOString(),
          };
        }

        // 4ª prioridade: checkout estornado/cancelado (ex: PAYER_MISMATCH após ter passado por processing!)
        const cancelledItem = validItems.find((item) => {
          const st = safePrimitiveString(item.status).toLowerCase();
          return st === 'cancelled' || st === 'canceled' || st === 'refunded' || st === 'failed';
        });
        if (cancelledItem) {
          const reasons = Array.isArray(cancelledItem.rejection_reasons)
            ? cancelledItem.rejection_reasons.map(safePrimitiveString).filter(Boolean)
            : undefined;
          return { status: 'FAILED', rejectionReasons: reasons };
        }

        return { status: 'PENDING' };
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
      if (res.status === 404) return { status: 'EXPIRED' };
      if (!res.ok) return null;

      const root = asPlainObject(await res.json());
      if (!root) return null;
      const chk = asPlainObject(root.checkout) ?? root;

      if (this.shouldRejectSandboxItem(chk.is_live, false)) {
        return { status: 'PENDING' };
      }

      const rawStatus = safePrimitiveString(chk.status).toLowerCase();
      if (rawStatus === 'completed') {
        return {
          status: 'SETTLED_CRYPTO',
          txHash: safeOptionalId(chk.blockchain_tx_id),
          cryptoAmount: this.extractCryptoAmountFromItem(chk),
        };
      }
      if (rawStatus === 'processing' || rawStatus === 'approved') {
        return { status: 'PIX_CONFIRMED' };
      }
      if (rawStatus === 'expired') {
        return { status: 'EXPIRED' };
      }
      if (
        rawStatus === 'cancelled' ||
        rawStatus === 'canceled' ||
        rawStatus === 'failed' ||
        rawStatus === 'refunded'
      ) {
        const reasons = Array.isArray(chk.rejection_reasons)
          ? chk.rejection_reasons.map(safePrimitiveString).filter(Boolean)
          : undefined;
        return { status: 'FAILED', rejectionReasons: reasons };
      }
      if (rawStatus === 'pending') {
        const effMs = this.computeEffectivePendingExpiresMs(chk);
        return {
          status: 'PENDING',
          activePendingExpiresAt: effMs > Date.now() ? new Date(effMs).toISOString() : undefined,
        };
      }
      return { status: 'PENDING' };
    } catch {
      return null;
    }
  }

  public async expireCharge(providerChargeId: string): Promise<boolean> {
    if (!providerChargeId.startsWith('prd_')) return true;
    if (!this.config.apiKey) return false;
    if (!this.tryAcquireRateSlot('background')) return false;

    try {
      const res = await fetch(
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
      return res.ok || res.status === 404;
    } catch {
      return false;
    }
  }

  private async fetchCheckoutSettlementDetails(checkoutId: string): Promise<{
    txHash?: string;
    cryptoAmount?: number;
  }> {
    if (!this.tryAcquireRateSlot('background')) {
      return {};
    }
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
      if (!res.ok) return {};
      const root = asPlainObject(await res.json());
      if (!root) return {};
      const chk = asPlainObject(root.checkout) ?? root;
      return {
        txHash: safeOptionalId(chk.blockchain_tx_id),
        cryptoAmount: this.extractCryptoAmountFromItem(chk),
      };
    } catch {
      return {};
    }
  }

  private extractHumanError(status: number, rawText: string): string {
    try {
      const parsed = JSON.parse(rawText) as Record<string, unknown>;
      const legacy =
        typeof parsed.response === 'object' && parsed.response
          ? safeOptionalId((parsed.response as Record<string, unknown>).errorMessage)
          : undefined;
      const errObj =
        typeof parsed.error === 'object' && parsed.error
          ? (parsed.error as Record<string, unknown>)
          : undefined;
      const code = safeOptionalId(errObj?.code) ?? '';
      const msg = legacy ?? safeOptionalId(errObj?.message) ?? rawText;
      return `DePix App (${status}${code ? ' ' + code : ''}): ${msg}`;
    } catch {
      return `DePix App (HTTP ${status}): ${rawText}`;
    }
  }
}
