import crypto from 'node:crypto';
import QRCode from 'qrcode';
import type {
  CreateChargeInput,
  CreateChargeOutput,
  IPixCryptoProvider,
  OrderStatus,
  WebhookSettlementEvent,
} from '../types/domain.ts';

/**
 * Integração homologada com a documentação oficial da DePix App API (https://depixapp.com/docs.md):
 *
 * Opera em 2 modos automáticos:
 * 1) MODO ZERO CPF NO WHATSAPP (quando `input.payerDocument` não é informado):
 *    Usa `POST /api/products` com `kind: "charge"` (que NÃO exige CPF na API!) e gera um
 *    Link Privado Único (`https://pay.depixapp.com/c/prd_...`) + QR Code. O pagador abre o link
 *    e paga sem enviar documento nenhum na conversa do WhatsApp, e o robô monitora via
 *    `GET /api/products/:id/checkouts` + Webhooks!
 * 2) MODO PIX COPIA E COLA DIRETO NO CHAT (quando `input.payerDocument` é informado):
 *    Usa `POST /api/checkouts` com `payer_tax_number`, extrai `data.pix.qr_code` (`000201...`),
 *    entrega o Pix Copia e Cola puro direto no WhatsApp e monitora `GET /api/checkouts/:id`
 *    desembrulhando `{ checkout: { status, blockchain_tx_id } }`.
 */
export class DePixAppProvider implements IPixCryptoProvider {
  public readonly name = 'depixapp' as const;
  public readonly requiresPayerDocument = false;
  private readonly config: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
  };

  constructor(config: { apiUrl: string; apiKey: string; webhookSecret: string }) {
    const cleanBase = config.apiUrl.replace(/\/+$/, '');
    this.config = {
      apiUrl: cleanBase.endsWith('/api') ? cleanBase : `${cleanBase}/api`,
      apiKey: config.apiKey.trim(),
      webhookSecret: config.webhookSecret.trim(),
    };
  }

  public isLiveKey(): boolean {
    return this.config.apiKey.startsWith('sk_live_');
  }

  public isTestKey(): boolean {
    return this.config.apiKey.startsWith('sk_test_');
  }

  public async createCharge(input: CreateChargeInput): Promise<CreateChargeOutput> {
    if (!this.config.apiKey) {
      throw new Error(
        'API_KEY_MISSING: Cole sua Chave de API da DePix App (sk_test_... ou sk_live_...) no Passo 1 do painel.'
      );
    }

    // Documentação oficial DePix App: mínimo R$ 5,00 (500 centavos) e máximo R$ 6.000,00 (600000 centavos)
    const amountInCents = Math.round(input.amountBrl * 100);
    if (amountInCents < 500) {
      throw new Error('MIN_AMOUNT_500: O valor mínimo na DePix App é de R$ 5,00.');
    }
    if (amountInCents > 600_000) {
      throw new Error('MAX_AMOUNT_600000: O valor máximo por chave Pix é de R$ 6.000,00.');
    }

    // expires_in no rail Pix: mín 300s (5 min), máx 1200s (20 min)
    const expiresInSeconds = Math.min(1200, Math.max(300, Math.round(input.expirationMinutes * 60)));
    // DePix exige que callback_url seja HTTPS público (rejeita localhost HTTP)
    const publicHttpsCallback =
      input.webhookUrl.startsWith('https://') && !input.webhookUrl.includes('localhost')
        ? input.webhookUrl
        : undefined;

    // Estimativa líquida oficial da documentação DePix: taxa de 2% + R$ 0,99
    const estimatedNet = Math.max(0, Math.round((input.amountBrl * 0.98 - 0.99) * 100) / 100);

    // MODO 2: Com CPF/CNPJ informado -> Gera Pix Copia e Cola `000201...` direto via POST /api/checkouts
    if (input.payerDocument) {
      const payload: Record<string, unknown> = {
        amount: amountInCents,
        payer_tax_number: input.payerDocument,
        payment_method: 'pix',
        description: `Pedido #${input.externalId}`,
        expires_in: expiresInSeconds,
        metadata: {
          external_id: input.externalId,
        },
      };
      if (publicHttpsCallback) {
        payload.callback_url = publicHttpsCallback;
      }

      const response = await fetch(`${this.config.apiUrl}/checkouts`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'Idempotency-Key': input.externalId,
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errBody = await response.text();
        throw new Error(this.extractHumanError(response.status, errBody));
      }

      // POST /api/checkouts retorna o objeto flat na raiz com `pix: { qr_code: "000201..." }`
      const data = (await response.json()) as Record<string, unknown>;
      const pixBlock =
        typeof data.pix === 'object' && data.pix ? (data.pix as Record<string, unknown>) : {};
      const pixCopyPaste = String(
        pixBlock.qr_code ?? data.pix_payload ?? data.qr_code ?? data.payment_url ?? ''
      );
      if (!pixCopyPaste) {
        throw new Error('Resposta da DePix App não retornou o payload Pix.');
      }

      const expiresAt = data.expires_at
        ? String(data.expires_at)
        : new Date(Date.now() + expiresInSeconds * 1000).toISOString();

      const pixQrCodeBase64 = await QRCode.toDataURL(pixCopyPaste, { width: 320, margin: 2 });

      return {
        providerChargeId: String(data.id ?? input.externalId),
        pixCopyPaste,
        pixQrCodeBase64,
        pixQrCodeUrl: pixBlock.qr_image_url ? String(pixBlock.qr_image_url) : undefined,
        paymentUrl: data.payment_url ? String(data.payment_url) : undefined,
        estimatedCryptoAmount: estimatedNet,
        expiresAt,
      };
    }

    // MODO 1 (Padrão Zero-CPF no WhatsApp): Cria Cobrança Privada Única (`kind: "charge"`) em POST /api/products
    const saoPauloToday = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Sao_Paulo',
    }).format(new Date());

    const chargePayload: Record<string, unknown> = {
      name: `Pagamento Pix ${input.externalId.slice(-6).toUpperCase()}`,
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

  /**
   * Validação oficial do cabeçalho `X-DePix-Signature: t=1717257600,v1=abc123...`
   * Assinatura calculada sobre `${timestamp}.${rawBody}` com HMAC-SHA256.
   */
  public verifyWebhookSignature(
    rawBody: string,
    headers: Record<string, string | string[] | undefined>
  ): boolean {
    const sig =
      headers['x-depix-signature'] ?? headers['x-webhook-signature'] ?? headers['x-signature'];
    if (!sig || typeof sig !== 'string' || !this.config.webhookSecret) {
      return false;
    }

    // Formato oficial DePix: t=<timestamp>,v1=<hex>
    const parts = sig.split(',').map((p) => p.trim());
    const tPart = parts.find((p) => p.startsWith('t='));
    const v1Part = parts.find((p) => p.startsWith('v1='));

    if (tPart && v1Part) {
      const timestamp = tPart.slice(2);
      const receivedV1 = v1Part.slice(3);
      const expectedHex = crypto
        .createHmac('sha256', this.config.webhookSecret)
        .update(`${timestamp}.${rawBody}`)
        .digest('hex');

      const a = Buffer.from(receivedV1, 'utf8');
      const b = Buffer.from(expectedHex, 'utf8');
      if (a.length !== b.length) return false;
      return crypto.timingSafeEqual(a, b);
    }

    // Fallback compatível caso enviado apenas sha256=<hex>
    const expectedPlain = crypto
      .createHmac('sha256', this.config.webhookSecret)
      .update(rawBody)
      .digest('hex');
    const cleanSig = sig.replace(/^sha256=/i, '').trim();
    const a = Buffer.from(cleanSig, 'utf8');
    const b = Buffer.from(expectedPlain, 'utf8');
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

    // Regra crítica da doc oficial: NUNCA liberar pedido real se `is_live: false` quando usando chave live!
    if (this.isLiveKey() && data.is_live === false) {
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

  /**
   * Consulta ativa do pagamento na DePix App (funciona tanto para `chk_...` quanto para `prd_...`!).
   */
  public async checkChargeStatus(providerChargeId: string): Promise<{
    status: OrderStatus;
    txHash?: string;
    cryptoAmount?: number;
    rejectionReasons?: string[];
  } | null> {
    if (!this.config.apiKey || !providerChargeId) return null;

    try {
      // Se foi gerado como Link Privado (`prd_...`), consulta os checkouts vinculados ao produto
      if (providerChargeId.startsWith('prd_')) {
        const res = await fetch(
          `${this.config.apiUrl}/products/${encodeURIComponent(providerChargeId)}/checkouts?limit=10`,
          {
            headers: {
              Authorization: `Bearer ${this.config.apiKey}`,
              Accept: 'application/json',
            },
          }
        );
        if (!res.ok) return null;
        const root = (await res.json()) as Record<string, unknown>;
        const list = Array.isArray(root.checkouts)
          ? (root.checkouts as Array<Record<string, unknown>>)
          : [];

        for (const item of list) {
          if (this.isLiveKey() && (item.is_live === false || item.is_live === 0)) continue;
          const st = String(item.status ?? '').toLowerCase();
          if (st === 'completed') {
            return {
              status: 'SETTLED_CRYPTO',
              txHash: item.blockchain_tx_id ? String(item.blockchain_tx_id) : undefined,
            };
          }
          if (st === 'processing' || st === 'approved') {
            return { status: 'PIX_CONFIRMED' };
          }
          if (st === 'cancelled') {
            const reasons = Array.isArray(item.rejection_reasons)
              ? item.rejection_reasons.map(String)
              : undefined;
            return { status: 'FAILED', rejectionReasons: reasons };
          }
        }
        return null;
      }

      // Consulta direta de checkout (`chk_...`) — resposta vem embrulhada em `{ checkout: { ... } }`!
      const res = await fetch(
        `${this.config.apiUrl}/checkouts/${encodeURIComponent(providerChargeId)}`,
        {
          headers: {
            Authorization: `Bearer ${this.config.apiKey}`,
            Accept: 'application/json',
          },
        }
      );
      if (!res.ok) return null;
      const root = (await res.json()) as Record<string, unknown>;
      const chk =
        typeof root.checkout === 'object' && root.checkout
          ? (root.checkout as Record<string, unknown>)
          : root;

      if (this.isLiveKey() && (chk.is_live === false || chk.is_live === 0)) {
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

  /**
   * Desativa automaticamente links privados expirados (`prd_...`) para impedir pagamento fora do prazo.
   */
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
        }
      );
    } catch {
      // Ignora falha de rede silenciosa ao desativar link expirado
    }
  }

  /**
   * Simula pagamento em chaves de teste (`sk_test_...`) usando o endpoint oficial da DePix App.
   */
  public async simulateSandboxPayment(providerChargeId: string): Promise<boolean> {
    if (!this.isTestKey() || !providerChargeId.startsWith('chk_')) return false;
    try {
      const res = await fetch(
        `${this.config.apiUrl}/checkouts/${encodeURIComponent(providerChargeId)}/simulate-payment`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${this.config.apiKey}`,
            Accept: 'application/json',
          },
        }
      );
      return res.ok;
    } catch {
      return false;
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
