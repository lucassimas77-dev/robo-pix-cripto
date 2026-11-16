import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import type {
  ChatSession,
  OrderStatus,
  OutgoingWhatsAppMessage,
  PixCryptoOrder,
  RuntimeAccountSettings,
  SupportedProviderName,
} from '../types/domain.ts';

export class OrderRepository {
  private db: DatabaseSync;

  constructor(dbPath = path.resolve(process.cwd(), 'data', 'automation.sqlite')) {
    if (dbPath !== ':memory:') {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }
    this.db = new DatabaseSync(dbPath);
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        external_id TEXT UNIQUE NOT NULL,
        provider TEXT NOT NULL,
        provider_charge_id TEXT NOT NULL,
        customer_phone TEXT NOT NULL,
        customer_jid TEXT,
        customer_name TEXT,
        payer_document TEXT,
        amount_brl REAL NOT NULL,
        estimated_crypto_amount REAL,
        crypto_asset TEXT NOT NULL,
        crypto_network TEXT NOT NULL,
        wallet_address TEXT NOT NULL,
        pix_copy_paste TEXT NOT NULL,
        pix_qr_code_base64 TEXT,
        pix_qr_code_url TEXT,
        payment_url TEXT,
        status TEXT NOT NULL,
        warning_sent INTEGER NOT NULL DEFAULT 0,
        tx_hash TEXT,
        end_to_end_id TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        paid_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_orders_phone_status ON orders(customer_phone, status);
      CREATE INDEX IF NOT EXISTS idx_orders_provider_charge ON orders(provider, provider_charge_id);

      CREATE TABLE IF NOT EXISTS chat_sessions (
        phone TEXT PRIMARY KEY,
        customer_jid TEXT,
        stage TEXT NOT NULL,
        draft_amount_brl REAL,
        draft_customer_name TEXT,
        pending_new_amount_brl REAL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS whatsapp_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT NOT NULL,
        direction TEXT NOT NULL,
        type TEXT NOT NULL,
        body TEXT NOT NULL,
        media_base64 TEXT,
        media_url TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS runtime_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        json_data TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS processed_webhook_events (
        event_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL
      );
    `);

    // Migrações seguras para bancos SQLite já criados anteriormente
    const safeAlter = [
      `ALTER TABLE orders ADD COLUMN customer_jid TEXT`,
      `ALTER TABLE orders ADD COLUMN payment_url TEXT`,
      `ALTER TABLE chat_sessions ADD COLUMN customer_jid TEXT`,
    ];
    for (const sql of safeAlter) {
      try {
        this.db.exec(sql);
      } catch {
        // Coluna já existe
      }
    }
  }

  public tryRecordWebhookEvent(eventId?: string): boolean {
    if (!eventId) return true;
    try {
      const res = this.db
        .prepare(
          `INSERT OR IGNORE INTO processed_webhook_events (event_id, created_at) VALUES (?, ?)`
        )
        .run(eventId, new Date().toISOString());
      return Number(res.changes) > 0;
    } catch {
      return true;
    }
  }

  public getRuntimeSettings(defaults: RuntimeAccountSettings): RuntimeAccountSettings {
    const row = this.db
      .prepare(`SELECT json_data FROM runtime_settings WHERE id = 1`)
      .get() as { json_data?: string } | undefined;

    if (!row?.json_data) return defaults;
    try {
      const parsed = JSON.parse(row.json_data) as Partial<RuntimeAccountSettings>;
      return { ...defaults, ...parsed };
    } catch {
      return defaults;
    }
  }

  public saveRuntimeSettings(settings: RuntimeAccountSettings): RuntimeAccountSettings {
    this.db
      .prepare(`
        INSERT INTO runtime_settings (id, json_data, updated_at)
        VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          json_data = excluded.json_data,
          updated_at = excluded.updated_at
      `)
      .run(JSON.stringify(settings), new Date().toISOString());
    return settings;
  }

  public createOrder(order: PixCryptoOrder): void {
    const stmt = this.db.prepare(`
      INSERT INTO orders (
        id, external_id, provider, provider_charge_id, customer_phone, customer_jid,
        customer_name, payer_document, amount_brl, estimated_crypto_amount,
        crypto_asset, crypto_network, wallet_address, pix_copy_paste,
        pix_qr_code_base64, pix_qr_code_url, payment_url, status, warning_sent,
        tx_hash, end_to_end_id, created_at, expires_at, paid_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `);

    stmt.run(
      order.id,
      order.externalId,
      order.provider,
      order.providerChargeId,
      order.customerPhone,
      order.customerJid ?? null,
      order.customerName ?? null,
      order.payerDocument ?? null,
      order.amountBrl,
      order.estimatedCryptoAmount ?? null,
      order.cryptoAsset,
      order.cryptoNetwork,
      order.walletAddress,
      order.pixCopyPaste,
      order.pixQrCodeBase64 ?? null,
      order.pixQrCodeUrl ?? null,
      order.paymentUrl ?? null,
      order.status,
      order.warningSent ? 1 : 0,
      order.txHash ?? null,
      order.endToEndId ?? null,
      order.createdAt,
      order.expiresAt,
      order.paidAt ?? null
    );
  }

  public getOrderById(id: string): PixCryptoOrder | null {
    const row = this.db.prepare(`SELECT * FROM orders WHERE id = ?`).get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? this.mapRowToOrder(row) : null;
  }

  public findOrderByWebhookIds(params: {
    provider: SupportedProviderName;
    providerChargeId?: string;
    externalId?: string;
  }): PixCryptoOrder | null {
    if (params.externalId) {
      const byExt = this.db
        .prepare(`SELECT * FROM orders WHERE external_id = ?`)
        .get(params.externalId) as Record<string, unknown> | undefined;
      if (byExt) return this.mapRowToOrder(byExt);
    }

    if (params.providerChargeId) {
      const byCharge = this.db
        .prepare(`SELECT * FROM orders WHERE provider = ? AND provider_charge_id = ?`)
        .get(params.provider, params.providerChargeId) as Record<string, unknown> | undefined;
      if (byCharge) return this.mapRowToOrder(byCharge);
    }

    return null;
  }

  public findActivePendingOrderByPhone(
    phone: string,
    nowIso = new Date().toISOString()
  ): PixCryptoOrder | null {
    const row = this.db
      .prepare(`
        SELECT * FROM orders
        WHERE customer_phone = ? AND status = 'PENDING' AND expires_at > ?
        ORDER BY created_at DESC
        LIMIT 1
      `)
      .get(phone, nowIso) as Record<string, unknown> | undefined;
    return row ? this.mapRowToOrder(row) : null;
  }

  public listPendingOrders(): PixCryptoOrder[] {
    const rows = this.db
      .prepare(`SELECT * FROM orders WHERE status = 'PENDING' ORDER BY expires_at ASC`)
      .all() as Array<Record<string, unknown>>;
    return rows.map((r) => this.mapRowToOrder(r));
  }

  public listActiveUnsettledOrders(): PixCryptoOrder[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM orders WHERE status IN ('PENDING', 'PIX_CONFIRMED') ORDER BY expires_at ASC`
      )
      .all() as Array<Record<string, unknown>>;
    return rows.map((r) => this.mapRowToOrder(r));
  }

  public listRecentOrders(limit = 50): PixCryptoOrder[] {
    const rows = this.db
      .prepare(`SELECT * FROM orders ORDER BY created_at DESC LIMIT ?`)
      .all(limit) as Array<Record<string, unknown>>;
    return rows.map((r) => this.mapRowToOrder(r));
  }

  public markWarningSent(orderId: string): void {
    this.db.prepare(`UPDATE orders SET warning_sent = 1 WHERE id = ?`).run(orderId);
  }

  public extendOrderExpiration(orderId: string, newExpiresAtIso: string): void {
    this.db
      .prepare(`UPDATE orders SET expires_at = ? WHERE id = ? AND expires_at < ?`)
      .run(newExpiresAtIso, orderId, newExpiresAtIso);
  }

  public updateOrderStatus(orderId: string, newStatus: OrderStatus): boolean {
    const result = this.db
      .prepare(`UPDATE orders SET status = ? WHERE id = ? AND status != ?`)
      .run(newStatus, orderId, newStatus);
    return Number(result.changes) > 0;
  }

  public applySettlementUpdate(params: {
    orderId: string;
    newStatus: OrderStatus;
    txHash?: string;
    endToEndId?: string;
    cryptoAmount?: number;
  }): { changed: boolean; updatedOrder: PixCryptoOrder | null } {
    const current = this.getOrderById(params.orderId);
    if (!current) return { changed: false, updatedOrder: null };

    // Estados terminais definitivos nunca retrocedem
    if (current.status === 'SETTLED_CRYPTO') {
      return { changed: false, updatedOrder: current };
    }
    if (current.status === params.newStatus) {
      return { changed: false, updatedOrder: current };
    }
    // Se já confirmou o pagamento do Pix, nunca volta para EXPIRED
    if (current.status === 'PIX_CONFIRMED' && params.newStatus === 'EXPIRED') {
      return { changed: false, updatedOrder: current };
    }

    const paidAt =
      params.newStatus === 'PIX_CONFIRMED' || params.newStatus === 'SETTLED_CRYPTO'
        ? current.paidAt || new Date().toISOString()
        : (current.paidAt ?? null);

    this.db
      .prepare(`
        UPDATE orders
        SET status = ?,
            tx_hash = COALESCE(?, tx_hash),
            end_to_end_id = COALESCE(?, end_to_end_id),
            estimated_crypto_amount = COALESCE(?, estimated_crypto_amount),
            paid_at = ?
        WHERE id = ?
      `)
      .run(
        params.newStatus,
        params.txHash ?? null,
        params.endToEndId ?? null,
        params.cryptoAmount ?? null,
        paidAt,
        params.orderId
      );

    return { changed: true, updatedOrder: this.getOrderById(params.orderId) };
  }

  // ==================== SESSÕES DE CONVERSA ====================

  public getSession(phone: string): ChatSession {
    const row = this.db
      .prepare(`SELECT * FROM chat_sessions WHERE phone = ?`)
      .get(phone) as Record<string, unknown> | undefined;

    if (!row) {
      return {
        phone,
        stage: 'IDLE',
        updatedAt: new Date().toISOString(),
      };
    }

    return {
      phone: String(row.phone),
      customerJid: row.customer_jid != null ? String(row.customer_jid) : undefined,
      stage: row.stage as ChatSession['stage'],
      draftAmountBrl: row.draft_amount_brl != null ? Number(row.draft_amount_brl) : undefined,
      draftCustomerName:
        row.draft_customer_name != null ? String(row.draft_customer_name) : undefined,
      pendingNewAmountBrl:
        row.pending_new_amount_brl != null ? Number(row.pending_new_amount_brl) : undefined,
      updatedAt: String(row.updated_at),
    };
  }

  public saveSession(session: ChatSession): void {
    this.db
      .prepare(`
        INSERT INTO chat_sessions (
          phone, customer_jid, stage, draft_amount_brl, draft_customer_name, pending_new_amount_brl, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(phone) DO UPDATE SET
          customer_jid = COALESCE(excluded.customer_jid, chat_sessions.customer_jid),
          stage = excluded.stage,
          draft_amount_brl = excluded.draft_amount_brl,
          draft_customer_name = excluded.draft_customer_name,
          pending_new_amount_brl = excluded.pending_new_amount_brl,
          updated_at = excluded.updated_at
      `)
      .run(
        session.phone,
        session.customerJid ?? null,
        session.stage,
        session.draftAmountBrl ?? null,
        session.draftCustomerName ?? null,
        session.pendingNewAmountBrl ?? null,
        new Date().toISOString()
      );
  }

  // ==================== HISTÓRICO DE MENSAGENS ====================

  public logMessage(msg: OutgoingWhatsAppMessage): void {
    this.db
      .prepare(`
        INSERT INTO whatsapp_messages (phone, direction, type, body, media_base64, media_url, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        msg.phone,
        msg.direction,
        msg.type,
        msg.body,
        msg.mediaBase64 ?? null,
        msg.mediaUrl ?? null,
        msg.createdAt
      );
  }

  /**
   * Retorna as `limit` mensagens MAIS RECENTES em ordem cronológica (ASC).
   */
  public listMessages(phone?: string, limit = 100): OutgoingWhatsAppMessage[] {
    const rows = phone
      ? (this.db
          .prepare(`
            SELECT * FROM (
              SELECT * FROM whatsapp_messages WHERE phone = ? ORDER BY id DESC LIMIT ?
            ) ORDER BY id ASC
          `)
          .all(phone, limit) as Array<Record<string, unknown>>)
      : (this.db
          .prepare(`
            SELECT * FROM (
              SELECT * FROM whatsapp_messages ORDER BY id DESC LIMIT ?
            ) ORDER BY id ASC
          `)
          .all(limit) as Array<Record<string, unknown>>);

    return rows.map((r) => ({
      id: Number(r.id),
      phone: String(r.phone),
      direction: r.direction as 'INBOUND' | 'OUTBOUND',
      type: r.type as 'TEXT' | 'IMAGE' | 'PIX_CODE',
      body: String(r.body),
      mediaBase64: r.media_base64 != null ? String(r.media_base64) : undefined,
      mediaUrl: r.media_url != null ? String(r.media_url) : undefined,
      createdAt: String(r.created_at),
    }));
  }

  public close(): void {
    this.db.close();
  }

  private mapRowToOrder(row: Record<string, unknown>): PixCryptoOrder {
    return {
      id: String(row.id),
      externalId: String(row.external_id),
      provider: row.provider as SupportedProviderName,
      providerChargeId: String(row.provider_charge_id),
      customerPhone: String(row.customer_phone),
      customerJid: row.customer_jid != null ? String(row.customer_jid) : undefined,
      customerName: row.customer_name != null ? String(row.customer_name) : undefined,
      payerDocument: row.payer_document != null ? String(row.payer_document) : undefined,
      amountBrl: Number(row.amount_brl),
      estimatedCryptoAmount:
        row.estimated_crypto_amount != null ? Number(row.estimated_crypto_amount) : undefined,
      cryptoAsset: String(row.crypto_asset),
      cryptoNetwork: String(row.crypto_network),
      walletAddress: String(row.wallet_address),
      pixCopyPaste: String(row.pix_copy_paste),
      pixQrCodeBase64:
        row.pix_qr_code_base64 != null ? String(row.pix_qr_code_base64) : undefined,
      pixQrCodeUrl: row.pix_qr_code_url != null ? String(row.pix_qr_code_url) : undefined,
      paymentUrl: row.payment_url != null ? String(row.payment_url) : undefined,
      status: row.status as OrderStatus,
      warningSent: Number(row.warning_sent) === 1,
      txHash: row.tx_hash != null ? String(row.tx_hash) : undefined,
      endToEndId: row.end_to_end_id != null ? String(row.end_to_end_id) : undefined,
      createdAt: String(row.created_at),
      expiresAt: String(row.expires_at),
      paidAt: row.paid_at != null ? String(row.paid_at) : undefined,
    };
  }
}
