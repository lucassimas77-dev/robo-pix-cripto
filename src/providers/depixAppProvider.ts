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
 * Integração com a API DePix App (https://api.depixapp.com/api/checkouts).
 *
 * Projetado especificamente para PRIVACIDADE e AUTOCUSTÓDIA:
 * - NÃO exige CPF, CNPJ nem nome do pagador (basta enviar o valor em centavos e `rail: "pix"`).
 * - Seu nome e sua conta bancária pessoal NÃO aparecem para quem paga o Pix.
 * - Os fundos caem diretamente como DePix na sua carteira autocustodiada na Liquid Network
 *   (transações confidenciais on-chain, com troca rápida para L-USDT ou Bitcoin via SideSwap/Aqua).
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
    this.config = config;
  }

  public async createCharge(input: CreateChargeInput): Promise<CreateChargeOutput> {
    if (!this.config.apiKey) {
      throw new Error('DEPIXAPP_API_KEY (sk_live_... ou sk_test_...) não configurada no .env.');
    }

    // DePix App trabalha com inteiros em centavos (ex: R$ 15,00 -> 1500)
    const amountInCents = Math.round(input.amountBrl * 100);

    const response = await fetch(`${this.config.apiUrl}/checkouts`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        amount: amountInCents,
        value: amountInCents,
        rail: 'pix',
        description: `Pedido #${input.externalId}`,
        metadata: {
          external_id: input.externalId,
          wallet_address: input.walletAddress,
        },
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Falha ao criar cobrança no DePix App (HTTP ${response.status}): ${errorText}`);
    }

    const data = (await response.json()) as Record<string, unknown>;

    // Extrai o BR Code Pix Copia e Cola direto (se retornado) ou link de pagamento
    const pixCopyPaste = String(
      data.qr_code ?? data.pix_code ?? data.brcode ?? data.payment_url ?? ''
    );
    if (!pixCopyPaste) {
      throw new Error('Resposta do DePix App não retornou código Pix nem URL de checkout.');
    }

    const expiresAt = data.expires_at
      ? String(data.expires_at)
      : new Date(Date.now() + input.expirationMinutes * 60_000).toISOString();

    const pixQrCodeBase64 = await QRCode.toDataURL(pixCopyPaste, {
      width: 320,
      margin: 2,
    });

    // Estimativa líquida (~98% após taxa típica da rede de liquidação)
    const estimatedCryptoAmount = Math.round(input.amountBrl * 0.98 * 100) / 100;

    return {
      providerChargeId: String(data.id ?? input.externalId),
      pixCopyPaste,
      pixQrCodeBase64,
      paymentUrl: data.payment_url ? String(data.payment_url) : undefined,
      estimatedCryptoAmount,
      expiresAt,
    };
  }

  public verifyWebhookSignature(
    rawBody: string,
    headers: Record<string, string | string[] | undefined>
  ): boolean {
    const sig =
      headers['x-depix-signature'] ?? headers['x-webhook-signature'] ?? headers['x-signature'];
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
    const data = (typeof root.data === 'object' && root.data ? root.data : root) as Record<
      string,
      unknown
    >;

    const rawStatus = String(data.status ?? root.event ?? '').toLowerCase();
    let newStatus: OrderStatus | null = null;

    if (
      rawStatus === 'completed' ||
      rawStatus === 'paid' ||
      rawStatus === 'checkout.completed' ||
      rawStatus === 'checkout.paid'
    ) {
      newStatus = 'SETTLED_CRYPTO';
    } else if (rawStatus === 'expired' || rawStatus === 'checkout.expired') {
      newStatus = 'EXPIRED';
    } else if (rawStatus === 'failed' || rawStatus === 'refunded') {
      newStatus = 'FAILED';
    }

    if (!newStatus) return null;

    const metadata =
      typeof data.metadata === 'object' && data.metadata
        ? (data.metadata as Record<string, unknown>)
        : {};

    return {
      provider: 'depixapp',
      providerChargeId: data.id ? String(data.id) : undefined,
      externalId: metadata.external_id
        ? String(metadata.external_id)
        : data.external_id
          ? String(data.external_id)
          : undefined,
      newStatus,
      txHash: data.tx_hash ? String(data.tx_hash) : data.txid ? String(data.txid) : undefined,
      cryptoAmount:
        data.net_amount != null ? Number(data.net_amount) / 100 : undefined,
      rawEventName: rawStatus,
    };
  }

  /**
   * Consulta ativa do pagamento no DePix App (dispensa configuração manual de Webhook).
   */
  public async checkChargeStatus(providerChargeId: string): Promise<{
    status: OrderStatus;
    txHash?: string;
    cryptoAmount?: number;
  } | null> {
    if (!this.config.apiKey || !providerChargeId) return null;
    try {
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
      const data = (await res.json()) as Record<string, unknown>;
      const rawStatus = String(data.status ?? '').toLowerCase();

      if (rawStatus === 'completed' || rawStatus === 'paid') {
        return {
          status: 'SETTLED_CRYPTO',
          txHash: data.tx_hash ? String(data.tx_hash) : undefined,
          cryptoAmount: data.net_amount != null ? Number(data.net_amount) / 100 : undefined,
        };
      }
      if (rawStatus === 'expired') return { status: 'EXPIRED' };
      if (rawStatus === 'failed' || rawStatus === 'refunded') return { status: 'FAILED' };
      return null;
    } catch {
      return null;
    }
  }
}
