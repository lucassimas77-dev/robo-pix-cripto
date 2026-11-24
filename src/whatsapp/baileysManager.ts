import fs from 'node:fs';
import path from 'node:path';
import QRCode from 'qrcode';
import pino from 'pino';
import {
  areJidsSameUser,
  Browsers,
  DisconnectReason,
  fetchLatestBaileysVersion,
  generateMessageIDV2,
  isLidUser,
  jidNormalizedUser,
  makeCacheableSignalKeyStore,
  makeWASocket,
  normalizeMessageContent,
  useMultiFileAuthState,
  WAMessageStatus,
} from '@whiskeysockets/baileys';
import type { proto, WAMessage, WASocket } from '@whiskeysockets/baileys';
import { OrderRepository } from '../database/orderRepository.ts';
import type { FilterMode } from '../types/domain.ts';
import {
  hasPixTriggerKeyword,
  isPostOrderFollowUpMessage,
  onlyDigits,
  parseActiveOrderMenuReply,
} from '../utils/cpfCnpjValidator.ts';

export type { FilterMode };

export interface WhatsAppActivityEvent {
  time: string;
  level: 'info' | 'ok' | 'warn' | 'error';
  summary: string;
}

export interface BaileysStatusSnapshot {
  state: 'DISCONNECTED' | 'CONNECTING' | 'QR_READY' | 'CONNECTED';
  qrCodeDataUrl?: string;
  connectedPhone?: string;
  filterMode: FilterMode;
  allowedTestPhone: string;
  lastError?: string;
  initialSyncDone: boolean;
  recentEvents: WhatsAppActivityEvent[];
}

const MAX_UNSCANNED_QR_CYCLES = 3;
const MAX_JID_MAP_ENTRIES = 5_000;
const MAX_TRACKED_MSG_IDS = 2_000;
const MAX_SENT_MESSAGE_CACHE = 250;
const MAX_RECENT_EVENTS = 25;
const RECENT_APPEND_WINDOW_MS = 90_000;
const SELF_ECHO_TTL_MS = 15_000;
const VERSION_FETCH_TIMEOUT_MS = 4_000;
const SESSION_FLOW_FRESHNESS_MS = 2 * 60 * 60 * 1000; // 2 horas
const SETTLED_MENU_TTL_MS = 5 * 60 * 1000; // 5 min para resposta "1"/"2" se a cobrança liquidou diante do menu
const RECENT_ORDER_CONTEXT_MS = 24 * 60 * 60 * 1000; // 24 horas para comandos pós-pagamento ("já paguei", "status")

function formatNowTimeSp(): string {
  return new Date().toLocaleTimeString('pt-BR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'America/Sao_Paulo',
  });
}

function maskPhoneForDiag(digits: string): string {
  const clean = onlyDigits(digits);
  if (clean.length >= 4) return `...${clean.slice(-4)}`;
  return 'desconhecido';
}

function previewTextForDiag(text: string): string {
  const single = text.replace(/\s+/g, ' ').trim();
  return single.length > 45 ? `${single.slice(0, 42)}...` : single;
}

function extractMessageTimestampMs(rawTs: unknown): number {
  if (typeof rawTs === 'number' && Number.isFinite(rawTs)) {
    return rawTs > 1_000_000_000_000 ? rawTs : rawTs * 1000;
  }
  if (typeof rawTs === 'bigint') {
    const n = Number(rawTs);
    return n > 1_000_000_000_000 ? n : n * 1000;
  }
  if (typeof rawTs === 'string' && rawTs.trim()) {
    const n = Number(rawTs);
    if (Number.isFinite(n)) return n > 1_000_000_000_000 ? n : n * 1000;
  }
  if (rawTs && typeof rawTs === 'object') {
    const obj = rawTs as { toNumber?: () => number; low?: number };
    if (typeof obj.toNumber === 'function') {
      const n = obj.toNumber();
      if (Number.isFinite(n)) return n > 1_000_000_000_000 ? n : n * 1000;
    }
    if (typeof obj.low === 'number' && Number.isFinite(obj.low)) {
      return obj.low > 1_000_000_000_000 ? obj.low : obj.low * 1000;
    }
  }
  return 0;
}

function getBrazilianPnJidVariants(phoneDigits: string): string[] {
  const clean = onlyDigits(phoneDigits);
  if (!clean) return [];
  const variants = new Set<string>([`${clean}@s.whatsapp.net`]);
  // Brasil com DDI 55: testa variante com e sem o 9º dígito para resolver LID
  if (clean.startsWith('55') && clean.length === 13 && clean[4] === '9') {
    variants.add(`${clean.slice(0, 4)}${clean.slice(5)}@s.whatsapp.net`);
  } else if (clean.startsWith('55') && clean.length === 12) {
    variants.add(`${clean.slice(0, 4)}9${clean.slice(4)}@s.whatsapp.net`);
  }
  return [...variants];
}

function extractTextFromWAMessage(rawMessage: proto.IMessage | null | undefined): string {
  if (!rawMessage) return '';
  let normalized = normalizeMessageContent(rawMessage);
  if (normalized?.protocolMessage?.editedMessage) {
    normalized = normalizeMessageContent(normalized.protocolMessage.editedMessage);
  }
  if (!normalized) return '';
  return (
    normalized.conversation ||
    normalized.extendedTextMessage?.text ||
    normalized.imageMessage?.caption ||
    normalized.videoMessage?.caption ||
    normalized.documentMessage?.caption ||
    normalized.documentWithCaptionMessage?.message?.documentMessage?.caption ||
    normalized.buttonsResponseMessage?.selectedDisplayText ||
    normalized.listResponseMessage?.title ||
    normalized.listResponseMessage?.singleSelectReply?.selectedRowId ||
    normalized.templateButtonReplyMessage?.selectedDisplayText ||
    ''
  ).trim();
}

export class BaileysDirectManager {
  private sock: WASocket | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private syncFallbackTimer: NodeJS.Timeout | null = null;
  private connectGeneration = 0;
  private state: BaileysStatusSnapshot['state'] = 'DISCONNECTED';
  private qrCodeDataUrl: string | undefined;
  private connectedPhone: string | undefined;
  private lastError: string | undefined;
  private filterMode: FilterMode = 'keyword_only';
  private allowedTestPhone = '';
  private intentionalStop = false;
  private hadOpenSession = false;
  private initialSyncDone = false;
  private connectedAtMs = 0;
  private unscannedQrCount = 0;
  private credsSaveChain: Promise<void> = Promise.resolve();

  private readonly jidMap = new Map<string, string>();
  private readonly altReplyJidMap = new Map<string, string>();
  private readonly lidToPnMap = new Map<string, string>();
  private readonly pnToLidMap = new Map<string, string>();
  private readonly sentMessageIds = new Set<string>();
  private readonly processedMessageIds = new Set<string>();
  private readonly sentMessageCache = new Map<string, proto.IMessage>();
  private readonly recentSelfOutboundTexts = new Map<string, number>();
  private readonly recentEvents: WhatsAppActivityEvent[] = [];
  private readonly authDir: string;
  private readonly repository: OrderRepository;
  private onIncomingTextCallback?: (params: {
    phone: string;
    customerJid: string;
    text: string;
    customerName?: string;
  }) => Promise<void>;

  constructor(
    repository: OrderRepository,
    authDir = path.resolve(process.cwd(), 'data', 'wa_auth'),
    initialFilter?: { filterMode?: FilterMode; allowedTestPhone?: string }
  ) {
    this.repository = repository;
    this.authDir = authDir;
    if (initialFilter?.filterMode) this.filterMode = initialFilter.filterMode;
    if (initialFilter?.allowedTestPhone) {
      this.allowedTestPhone = onlyDigits(initialFilter.allowedTestPhone);
    }
  }

  public setIncomingHandler(
    handler: (params: {
      phone: string;
      customerJid: string;
      text: string;
      customerName?: string;
    }) => Promise<void>
  ): void {
    this.onIncomingTextCallback = handler;
  }

  public getStatus(): BaileysStatusSnapshot {
    return {
      state: this.state,
      qrCodeDataUrl: this.qrCodeDataUrl,
      connectedPhone: this.connectedPhone,
      filterMode: this.filterMode,
      allowedTestPhone: this.allowedTestPhone,
      lastError: this.lastError,
      initialSyncDone: this.initialSyncDone,
      recentEvents: this.recentEvents.slice(0, MAX_RECENT_EVENTS),
    };
  }

  public updateFilterSettings(params: {
    filterMode?: FilterMode;
    allowedTestPhone?: string;
  }): BaileysStatusSnapshot {
    if (params.filterMode === 'keyword_only' || params.filterMode === 'all') {
      this.filterMode = params.filterMode;
    }
    if (params.allowedTestPhone !== undefined) {
      this.allowedTestPhone = onlyDigits(params.allowedTestPhone);
    }
    const modeLabel = this.filterMode === 'all' ? 'Responder todas' : 'Só com Pix/Pagar';
    const phoneLabel = this.allowedTestPhone
      ? `restrito a ...${this.allowedTestPhone.slice(-4)}`
      : 'qualquer número';
    this.recordEvent('info', `Filtro atualizado: ${modeLabel} (${phoneLabel}).`);
    return this.getStatus();
  }

  public isConnected(): boolean {
    return this.state === 'CONNECTED' && this.sock !== null;
  }

  public isConnecting(): boolean {
    return this.state === 'CONNECTING';
  }

  private recordEvent(level: WhatsAppActivityEvent['level'], summary: string): void {
    this.recentEvents.unshift({
      time: formatNowTimeSp(),
      level,
      summary,
    });
    if (this.recentEvents.length > MAX_RECENT_EVENTS) {
      this.recentEvents.length = MAX_RECENT_EVENTS;
    }
  }

  private rememberBoundedSet(set: Set<string>, value: string, maxEntries: number): void {
    if (!value) return;
    if (set.has(value)) {
      set.delete(value);
    } else if (set.size >= maxEntries) {
      const oldest = set.values().next().value;
      if (oldest !== undefined) set.delete(oldest);
    }
    set.add(value);
  }

  private rememberBoundedMap<V>(map: Map<string, V>, key: string, value: V, maxEntries: number): void {
    if (!key) return;
    if (map.has(key)) {
      map.delete(key);
    } else if (map.size >= maxEntries) {
      const oldest = map.keys().next().value;
      if (oldest !== undefined) map.delete(oldest);
    }
    map.set(key, value);
  }

  private rememberLidPnPair(lidJid?: string | null, pnJid?: string | null): void {
    if (!lidJid || !pnJid) return;
    const normLid = jidNormalizedUser(lidJid) || lidJid;
    const normPn = jidNormalizedUser(pnJid) || pnJid;
    if (!normLid.endsWith('@lid') || !normPn.endsWith('@s.whatsapp.net')) return;
    const lidDigits = onlyDigits(normLid.split('@')[0]?.split(':')[0] || '');
    const pnDigits = onlyDigits(normPn.split('@')[0]?.split(':')[0] || '');
    if (lidDigits.length >= 8 && pnDigits.length >= 8) {
      this.rememberBoundedMap(this.lidToPnMap, lidDigits, pnDigits, MAX_JID_MAP_ENTRIES);
      this.rememberBoundedMap(this.pnToLidMap, pnDigits, normLid, MAX_JID_MAP_ENTRIES);
    }
  }

  private rememberSentMessage(messageId?: string | null, message?: proto.IMessage | null): void {
    if (!messageId) return;
    this.rememberBoundedSet(this.sentMessageIds, messageId, MAX_TRACKED_MSG_IDS);
    if (message) {
      this.rememberBoundedMap(this.sentMessageCache, messageId, message, MAX_SENT_MESSAGE_CACHE);
    }
  }

  private recordSelfOutboundText(text: string): void {
    const clean = text.trim();
    if (!clean) return;
    const now = Date.now();
    for (const [k, exp] of this.recentSelfOutboundTexts.entries()) {
      if (exp <= now) this.recentSelfOutboundTexts.delete(k);
    }
    this.rememberBoundedMap(this.recentSelfOutboundTexts, clean, now + SELF_ECHO_TTL_MS, 50);
  }

  private isRecentSelfOutboundEcho(text: string): boolean {
    const clean = text.trim();
    const exp = this.recentSelfOutboundTexts.get(clean);
    if (!exp) return false;
    if (exp <= Date.now()) {
      this.recentSelfOutboundTexts.delete(clean);
      return false;
    }
    return true;
  }

  private evaluateFilterDecision(
    senderDigits: string,
    text: string,
    nowMs = Date.now(),
    matchedAllowedViaLid = false
  ): { allow: boolean; reason?: 'short_phone' | 'allowed_test_phone' | 'keyword_only' } {
    if (senderDigits.length < 8) {
      return { allow: false, reason: 'short_phone' };
    }

    if (this.allowedTestPhone && !matchedAllowedViaLid) {
      // Fail-closed: se o filtro está preenchido mas tem menos de 8 dígitos válidos, bloqueia tudo!
      if (this.allowedTestPhone.length < 8) {
        return { allow: false, reason: 'allowed_test_phone' };
      }
      if (this.allowedTestPhone.slice(-8) !== senderDigits.slice(-8)) {
        return { allow: false, reason: 'allowed_test_phone' };
      }
    }

    if (this.filterMode === 'keyword_only') {
      const session = this.repository.getSession(senderDigits);
      const activeOrder = this.repository.findActivePendingOrderByPhone(
        senderDigits,
        new Date(nowMs).toISOString()
      );
      const sessionAgeMs = nowMs - new Date(session.updatedAt).getTime();
      const isFreshSession =
        session.stage !== 'IDLE' &&
        Number.isFinite(sessionAgeMs) &&
        sessionAgeMs < SESSION_FLOW_FRESHNESS_MS;

      if (isFreshSession || activeOrder !== null || hasPixTriggerKeyword(text)) {
        return { allow: true };
      }

      if (
        session.draftAmountBrl === -2 &&
        Number.isFinite(sessionAgeMs) &&
        sessionAgeMs <= SETTLED_MENU_TTL_MS &&
        parseActiveOrderMenuReply(text).choice !== 'none'
      ) {
        return { allow: true };
      }

      const recentOrder = this.repository.findMostRecentOrderByPhone(senderDigits);
      const hasRecentOrderContext =
        recentOrder !== null &&
        recentOrder.status !== 'CANCELLED' &&
        (recentOrder.status === 'PIX_CONFIRMED' ||
          nowMs - new Date(recentOrder.createdAt).getTime() < RECENT_ORDER_CONTEXT_MS);

      if (hasRecentOrderContext && isPostOrderFollowUpMessage(text)) {
        return { allow: true };
      }
      return { allow: false, reason: 'keyword_only' };
    }

    return { allow: true };
  }

  public shouldForwardIncomingMessage(
    senderDigits: string,
    text: string,
    nowMs = Date.now()
  ): boolean {
    return this.evaluateFilterDecision(senderDigits, text, nowMs).allow;
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private clearSyncFallbackTimer(): void {
    if (this.syncFallbackTimer) {
      clearTimeout(this.syncFallbackTimer);
      this.syncFallbackTimer = null;
    }
  }

  private rememberJid(phoneDigits: string, jid: string, altJid?: string): void {
    this.rememberBoundedMap(this.jidMap, phoneDigits, jid, MAX_JID_MAP_ENTRIES);
    if (altJid && altJid !== jid && altJid.includes('@')) {
      this.rememberBoundedMap(this.altReplyJidMap, phoneDigits, altJid, MAX_JID_MAP_ENTRIES);
    }
  }

  private async waitForConnected(timeoutMs = 4_500): Promise<boolean> {
    if (this.isConnected()) return true;
    if (this.state !== 'CONNECTING') return false;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 250));
      if (this.isConnected()) return true;
      if (this.state !== 'CONNECTING') return false;
    }
    return this.isConnected();
  }

  public async startConnection(resetQrAttempts = true): Promise<BaileysStatusSnapshot> {
    if (this.state === 'CONNECTING' || this.state === 'QR_READY' || this.state === 'CONNECTED') {
      return this.getStatus();
    }

    const gen = ++this.connectGeneration;
    this.clearReconnectTimer();
    this.clearSyncFallbackTimer();
    if (resetQrAttempts) {
      this.unscannedQrCount = 0;
    }

    this.intentionalStop = false;
    await this.openSocket(gen);
    return this.getStatus();
  }

  private async openSocket(gen: number): Promise<void> {
    this.state = 'CONNECTING';
    this.lastError = undefined;
    this.initialSyncDone = false;

    try {
      fs.mkdirSync(this.authDir, { recursive: true });
      await this.credsSaveChain;
      const { state: authState, saveCreds } = await useMultiFileAuthState(this.authDir);
      if (this.intentionalStop || gen !== this.connectGeneration) {
        return;
      }

      let version: [number, number, number] | undefined;
      try {
        const latest = await Promise.race([
          fetchLatestBaileysVersion(),
          new Promise<null>((resolve) => setTimeout(() => resolve(null), VERSION_FETCH_TIMEOUT_MS)),
        ]);
        if (latest && latest.version) {
          version = latest.version;
        }
      } catch {
        // Fallback embutido do Baileys v7
      }

      if (this.intentionalStop || gen !== this.connectGeneration) {
        return;
      }

      const logger = pino({ level: 'error' });
      const sock = makeWASocket({
        ...(version ? { version } : {}),
        auth: {
          creds: authState.creds,
          keys: makeCacheableSignalKeyStore(authState.keys, logger),
        },
        logger,
        browser: Browsers.ubuntu('Chrome'),
        countryCode: 'BR',
        emitOwnEvents: false,
        syncFullHistory: false,
        generateHighQualityLinkPreview: false,
        getMessage: async (key) => {
          if (!key.id) return undefined;
          return this.sentMessageCache.get(key.id);
        },
      });

      this.sock = sock;

      sock.ev.on('creds.update', () => {
        if (this.intentionalStop || gen !== this.connectGeneration) return;
        this.credsSaveChain = this.credsSaveChain
          .catch(() => {})
          .then(() => saveCreds())
          .catch((err) => {
            console.error('[WhatsApp QR] Erro ao salvar credenciais:', err);
          });
      });

      sock.ev.on('lid-mapping.update', ({ lid, pn }) => {
        if (this.sock !== sock || gen !== this.connectGeneration) return;
        this.rememberLidPnPair(lid, pn);
      });

      const ingestContacts = (contacts: Array<{ id?: string; lid?: string; phoneNumber?: string }>) => {
        for (const c of contacts) {
          if (c.lid && c.phoneNumber) {
            this.rememberLidPnPair(c.lid, c.phoneNumber);
          } else if (c.id && c.lid) {
            this.rememberLidPnPair(c.lid, c.id);
          } else if (c.id && c.phoneNumber) {
            this.rememberLidPnPair(c.id, c.phoneNumber);
          }
        }
      };

      sock.ev.on('contacts.upsert', (contacts) => {
        if (this.sock !== sock || gen !== this.connectGeneration) return;
        ingestContacts(contacts);
      });

      sock.ev.on('contacts.update', (contacts) => {
        if (this.sock !== sock || gen !== this.connectGeneration) return;
        ingestContacts(contacts);
      });

      sock.ev.on('messaging-history.set', ({ contacts }) => {
        if (this.sock !== sock || gen !== this.connectGeneration) return;
        if (Array.isArray(contacts) && contacts.length > 0) {
          ingestContacts(contacts);
        }
        if (!this.initialSyncDone) {
          this.initialSyncDone = true;
          this.clearSyncFallbackTimer();
          this.recordEvent('ok', 'Sincronização inicial do WhatsApp concluída! Pronto para atender.');
        }
      });

      sock.ev.on('messages.update', (updates) => {
        if (this.sock !== sock || gen !== this.connectGeneration) return;
        for (const item of updates) {
          if (item.key?.fromMe && item.update?.status === WAMessageStatus.ERROR) {
            const label = maskPhoneForDiag(item.key.remoteJid || '');
            this.recordEvent(
              'error',
              `⚠️ WhatsApp rejeitou entrega da resposta para ${label} (ACK erro — verifique restrição na conta ou tente novamente).`
            );
          }
        }
      });

      sock.ev.on('connection.update', async (update) => {
        try {
          if (this.sock !== sock || gen !== this.connectGeneration) return;

          const { connection, lastDisconnect, qr, receivedPendingNotifications } = update;

          if (receivedPendingNotifications && !this.initialSyncDone && this.state === 'CONNECTED') {
            this.clearSyncFallbackTimer();
            this.syncFallbackTimer = setTimeout(() => {
              if (this.sock === sock && gen === this.connectGeneration && !this.initialSyncDone) {
                this.initialSyncDone = true;
                this.recordEvent('ok', 'WhatsApp pronto para receber e responder mensagens!');
              }
            }, 3_000);
          }

          if (qr) {
            this.hadOpenSession = false;
            this.connectedPhone = undefined;
            this.unscannedQrCount++;
            if (this.unscannedQrCount > MAX_UNSCANNED_QR_CYCLES) {
              this.intentionalStop = true;
              try {
                sock.end(undefined);
              } catch {
                // Ignora
              }
              this.sock = null;
              this.qrCodeDataUrl = undefined;
              this.state = 'DISCONNECTED';
              this.lastError =
                'QR Code expirou por falta de leitura. Clique em "Gerar QR Code" para tentar novamente.';
              this.recordEvent('warn', 'QR Code expirou sem leitura. Clique em "Gerar QR Code".');
              return;
            }
            const dataUrl = await QRCode.toDataURL(qr, { width: 280, margin: 2 });
            if (this.sock !== sock || gen !== this.connectGeneration || this.intentionalStop) {
              return;
            }
            this.qrCodeDataUrl = dataUrl;
            this.state = 'QR_READY';
            this.recordEvent('info', 'QR Code gerado — escaneie pelo celular em Aparelhos Conectados.');
          }

          if (connection === 'open') {
            this.hadOpenSession = true;
            this.unscannedQrCount = 0;
            this.state = 'CONNECTED';
            this.connectedAtMs = Date.now();
            this.qrCodeDataUrl = undefined;
            this.lastError = undefined;
            const rawId = sock.user?.id || '';
            this.connectedPhone = onlyDigits(
              rawId.split('@')[0]?.split(':')[0]?.split('_')[0] || ''
            );
            if (sock.user?.lid && sock.user?.id) {
              this.rememberLidPnPair(sock.user.lid, sock.user.id);
            }
            this.clearSyncFallbackTimer();
            this.syncFallbackTimer = setTimeout(() => {
              if (this.sock === sock && gen === this.connectGeneration && !this.initialSyncDone) {
                this.initialSyncDone = true;
                this.recordEvent('ok', 'WhatsApp pronto para receber e responder mensagens!');
              }
            }, 22_000);
            this.recordEvent(
              'ok',
              `WhatsApp conectado (+${this.connectedPhone})! Sincronizando contatos...`
            );
            console.log(`[WhatsApp QR] Conectado com sucesso! Número: +${this.connectedPhone}`);
          }

          if (connection === 'close') {
            this.sock = null;
            this.qrCodeDataUrl = undefined;
            this.clearSyncFallbackTimer();
            const statusCode = (
              lastDisconnect?.error as { output?: { statusCode?: number } } | undefined
            )?.output?.statusCode;

            if (statusCode === DisconnectReason.loggedOut) {
              this.clearAuthFolder();
              this.hadOpenSession = false;
              this.initialSyncDone = false;
              this.state = 'DISCONNECTED';
              this.connectedPhone = undefined;
              this.lastError = 'Sessão desconectada pelo celular. Gere um novo QR Code.';
              this.recordEvent('warn', 'Sessão encerrada pelo celular (401). Gere um novo QR Code.');
            } else if (statusCode === DisconnectReason.connectionReplaced) {
              this.initialSyncDone = false;
              this.state = 'DISCONNECTED';
              this.lastError =
                'Conexão substituída por outra sessão aberta. Clique em "Gerar QR Code" se quiser reconectar aqui.';
              this.recordEvent('warn', 'Sessão substituída em outro lugar (440).');
            } else if (!this.intentionalStop && gen === this.connectGeneration) {
              const isRestartRequired = statusCode === DisconnectReason.restartRequired;
              const delayMs = isRestartRequired ? 500 : 3_000;
              this.state = isRestartRequired ? 'CONNECTING' : 'DISCONNECTED';
              this.recordEvent(
                'info',
                isRestartRequired
                  ? 'QR lido! Concluindo conexão segura com o WhatsApp...'
                  : `Conexão oscilou (código ${statusCode ?? '?'}). Reconectando em 3s...`
              );
              await this.credsSaveChain;
              this.clearReconnectTimer();
              this.reconnectTimer = setTimeout(() => {
                this.reconnectTimer = null;
                if (!this.intentionalStop && gen === this.connectGeneration) {
                  this.openSocket(gen).catch((err) => {
                    console.error('[WhatsApp QR] Falha ao reconectar sessão:', err);
                  });
                }
              }, delayMs);
            } else {
              this.state = 'DISCONNECTED';
            }
          }
        } catch (err) {
          console.error('[WhatsApp QR] Erro em connection.update:', err);
        }
      });

      sock.ev.on('messages.upsert', async ({ messages, type }) => {
        if (this.sock !== sock || gen !== this.connectGeneration) return;
        await this.handleUpsertMessages(messages, type, sock);
      });
    } catch (err) {
      if (gen === this.connectGeneration && !this.intentionalStop) {
        this.state = 'DISCONNECTED';
        this.lastError = err instanceof Error ? err.message : String(err);
        this.recordEvent('error', `Erro ao conectar WhatsApp: ${this.lastError}`);
      }
    }
  }

  public async handleUpsertMessages(
    messages: WAMessage[],
    type: string,
    sockOverride?: Partial<WASocket> | null
  ): Promise<void> {
    const activeSock = sockOverride ?? this.sock;
    const nowMs = Date.now();

    for (const msg of messages) {
      try {
        const msgId = msg.key?.id || '';
        if (msgId && (this.sentMessageIds.has(msgId) || this.processedMessageIds.has(msgId))) {
          continue;
        }

        if (type !== 'notify') {
          if (type !== 'append') continue;
          const msgTsMs = extractMessageTimestampMs(msg.messageTimestamp);
          const isRecentEnough =
            msgTsMs > 0 &&
            nowMs - msgTsMs <= RECENT_APPEND_WINDOW_MS &&
            (this.connectedAtMs === 0 || msgTsMs >= this.connectedAtMs - 15_000);
          if (!isRecentEnough) continue;
        }

        const rawRemoteJid = msg.key?.remoteJid || '';
        const remoteJid = jidNormalizedUser(rawRemoteJid) || rawRemoteJid;
        if (
          !remoteJid ||
          remoteJid.endsWith('@g.us') ||
          remoteJid.endsWith('@broadcast') ||
          remoteJid.endsWith('@newsletter') ||
          remoteJid.endsWith('@bot')
        ) {
          continue;
        }

        const rawAltJid = (msg.key as Record<string, unknown> | undefined)?.remoteJidAlt;
        const altJid =
          typeof rawAltJid === 'string' && rawAltJid.includes('@')
            ? jidNormalizedUser(rawAltJid) || rawAltJid
            : '';

        const meId = activeSock?.user?.id || '';
        const meLid = activeSock?.user?.lid || '';
        const isSameAsMe = (jid: string): boolean => {
          if (!jid) return false;
          return Boolean(
            (meId && areJidsSameUser(jid, meId)) || (meLid && areJidsSameUser(jid, meLid))
          );
        };
        const isSelfChat = isSameAsMe(remoteJid) || (altJid ? isSameAsMe(altJid) : false);

        // Falha temporária de descriptografia Signal (CIPHERTEXT = 2): registra diagnóstico e aguarda retry
        if (!msg.message) {
          if (msg.messageStubType === 2 && !msg.key?.fromMe) {
            this.recordEvent(
              'warn',
              `⚠️ Mensagem criptografada de ${maskPhoneForDiag(remoteJid)} aguardando reenvio automático de chave Signal...`
            );
          }
          continue;
        }

        if (msg.key?.fromMe && !isSelfChat) {
          // Nunca responder mensagens enviadas pelo dono para outros contatos!
          continue;
        }

        const text = extractTextFromWAMessage(msg.message);
        if (!text) continue;

        if (msg.key?.fromMe && isSelfChat && this.isRecentSelfOutboundEcho(text)) {
          if (msgId) this.rememberBoundedSet(this.processedMessageIds, msgId, MAX_TRACKED_MSG_IDS);
          continue;
        }

        // Resolução de telefone real (PN) mesmo quando o WhatsApp entrega via @lid
        let pnJid = '';
        if (isSelfChat && meId && meId.includes('@s.whatsapp.net')) {
          pnJid = jidNormalizedUser(meId) || meId;
        } else if (remoteJid.endsWith('@s.whatsapp.net')) {
          pnJid = remoteJid;
        } else if (altJid.endsWith('@s.whatsapp.net')) {
          pnJid = altJid;
          if (isLidUser(remoteJid) || remoteJid.endsWith('@lid')) {
            this.rememberLidPnPair(remoteJid, pnJid);
          }
        } else if (isLidUser(remoteJid) || remoteJid.endsWith('@lid') || remoteJid.endsWith('@hosted.lid')) {
          const lidUserDigits = onlyDigits(remoteJid.split('@')[0]?.split(':')[0] || '');
          const cachedPn = this.lidToPnMap.get(lidUserDigits);
          if (cachedPn) {
            pnJid = `${cachedPn}@s.whatsapp.net`;
          } else {
            try {
              const resolvedPn = await activeSock?.signalRepository?.lidMapping?.getPNForLID?.(
                remoteJid
              );
              if (resolvedPn && resolvedPn.includes('@')) {
                pnJid = jidNormalizedUser(resolvedPn) || resolvedPn;
                this.rememberLidPnPair(remoteJid, pnJid);
              }
            } catch {
              // Segue com fallback
            }
          }
        }

        const bestJidForDigits = pnJid || altJid || remoteJid;
        const userPart = bestJidForDigits.split('@')[0]?.split(':')[0]?.split('_')[0] || '';
        const senderDigits = onlyDigits(userPart);
        if (senderDigits.length < 8) continue;

        const alternateReplyJid = pnJid && pnJid !== remoteJid ? pnJid : altJid || undefined;
        this.rememberJid(senderDigits, remoteJid, alternateReplyJid);

        // Fallback extra: se allowedTestPhone está ativo e o remetente veio só como @lid sem PN resolvido,
        // tenta resolver o LID correspondente ao allowedTestPhone (com e sem 9º dígito BR)
        let matchedAllowedViaLid = false;
        if (
          this.allowedTestPhone &&
          this.allowedTestPhone.length >= 8 &&
          this.allowedTestPhone.slice(-8) !== senderDigits.slice(-8) &&
          !pnJid &&
          (isLidUser(remoteJid) || remoteJid.endsWith('@lid'))
        ) {
          const cachedAllowedLid = this.pnToLidMap.get(this.allowedTestPhone);
          if (cachedAllowedLid && areJidsSameUser(cachedAllowedLid, remoteJid)) {
            matchedAllowedViaLid = true;
          } else if (activeSock?.signalRepository?.lidMapping?.getLIDForPN) {
            for (const pnVariant of getBrazilianPnJidVariants(this.allowedTestPhone)) {
              try {
                const resolvedLid = await activeSock.signalRepository.lidMapping.getLIDForPN(
                  pnVariant
                );
                if (resolvedLid) {
                  this.rememberLidPnPair(resolvedLid, pnVariant);
                  if (areJidsSameUser(resolvedLid, remoteJid)) {
                    matchedAllowedViaLid = true;
                    break;
                  }
                }
              } catch {
                // Ignora falha pontual de USync
              }
            }
          }
        }

        const senderLabel = isSelfChat
          ? 'Você (chat próprio)'
          : `contato ${maskPhoneForDiag(senderDigits)}`;
        const preview = previewTextForDiag(text);

        const decision = this.evaluateFilterDecision(
          senderDigits,
          text,
          nowMs,
          matchedAllowedViaLid
        );
        if (!decision.allow) {
          if (msgId) this.rememberBoundedSet(this.processedMessageIds, msgId, MAX_TRACKED_MSG_IDS);
          if (decision.reason === 'allowed_test_phone') {
            this.recordEvent(
              'warn',
              `⏭️ Ignorada de ${senderLabel} ("${preview}"): teste restrito ao número ...${this.allowedTestPhone.slice(-4)}.`
            );
          } else if (decision.reason === 'keyword_only') {
            this.recordEvent(
              'info',
              `⏭️ Ignorada de ${senderLabel} ("${preview}"): modo filtro ativo (aguardando "Pix" ou "Pagar").`
            );
          }
          continue;
        }

        if (msgId) this.rememberBoundedSet(this.processedMessageIds, msgId, MAX_TRACKED_MSG_IDS);
        this.recordEvent('info', `📩 Recebida de ${senderLabel}: "${preview}" ➔ Processando...`);

        if (this.onIncomingTextCallback) {
          await this.onIncomingTextCallback({
            phone: senderDigits,
            customerJid: remoteJid,
            text,
            customerName: msg.pushName || undefined,
          });
        }
      } catch (err) {
        console.error('[WhatsApp QR] Erro ao processar mensagem recebida:', err);
        this.recordEvent(
          'error',
          `❌ Erro ao processar mensagem recebida: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }
  }

  public async disconnect(wipeSession = false): Promise<BaileysStatusSnapshot> {
    this.connectGeneration++;
    this.intentionalStop = true;
    this.clearReconnectTimer();
    this.clearSyncFallbackTimer();
    const currentSock = this.sock;
    this.sock = null;

    if (currentSock) {
      try {
        if (wipeSession) {
          await currentSock.logout();
        } else {
          currentSock.end(undefined);
        }
      } catch {
        // Ignora
      }
    }
    if (wipeSession) {
      this.clearAuthFolder();
      this.connectedPhone = undefined;
      this.hadOpenSession = false;
    }
    this.initialSyncDone = false;
    this.qrCodeDataUrl = undefined;
    this.state = 'DISCONNECTED';
    this.recordEvent('info', 'WhatsApp desconectado manualmente.');
    return this.getStatus();
  }

  private isTargetSelfChat(targetJid: string): boolean {
    const meId = this.sock?.user?.id || '';
    const meLid = this.sock?.user?.lid || '';
    return Boolean(
      (meId && areJidsSameUser(targetJid, meId)) || (meLid && areJidsSameUser(targetJid, meLid))
    );
  }

  private async sendMessageWithFallback(
    phoneDigits: string,
    preferredJid: string | undefined,
    buildContent: () => Parameters<WASocket['sendMessage']>[1],
    outboundTextForEchoGuard: string
  ): Promise<boolean> {
    const ready = await this.waitForConnected(4_500);
    const label = maskPhoneForDiag(phoneDigits);
    if (!ready || !this.sock) {
      this.recordEvent('error', `❌ Não foi possível responder ${label}: WhatsApp desconectado.`);
      return false;
    }

    const primaryJid = this.resolveJid(phoneDigits, preferredJid);
    const cleanPhone = onlyDigits(phoneDigits);
    const altCandidate = this.altReplyJidMap.get(cleanPhone);
    const candidates =
      altCandidate && altCandidate !== primaryJid ? [primaryJid, altCandidate] : [primaryJid];

    let lastErr: unknown;
    for (let i = 0; i < candidates.length; i++) {
      const targetJid = candidates[i];
      const msgId = generateMessageIDV2(this.sock.user?.id);
      this.rememberSentMessage(msgId);
      if (this.isTargetSelfChat(targetJid) && outboundTextForEchoGuard) {
        this.recordSelfOutboundText(outboundTextForEchoGuard);
      }
      try {
        const sent = await this.sock.sendMessage(targetJid, buildContent(), { messageId: msgId });
        this.rememberSentMessage(sent?.key?.id || msgId, sent?.message);
        const destLabel = this.isTargetSelfChat(targetJid) ? 'Você (chat próprio)' : label;
        this.recordEvent(
          'ok',
          i === 0
            ? `✅ Resposta enviada para ${destLabel}.`
            : `✅ Resposta enviada para ${destLabel} (via endereço alternativo).`
        );
        return true;
      } catch (err) {
        lastErr = err;
      }
    }

    console.error('[WhatsApp QR] Erro ao enviar mensagem:', lastErr);
    this.recordEvent(
      'error',
      `❌ Falha ao enviar para ${label}: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`
    );
    return false;
  }

  public async sendText(
    phoneDigits: string,
    text: string,
    preferredJid?: string
  ): Promise<boolean> {
    return this.sendMessageWithFallback(phoneDigits, preferredJid, () => ({ text }), text);
  }

  public async sendImageWithCaption(
    phoneDigits: string,
    dataUriBase64: string,
    caption: string,
    preferredJid?: string
  ): Promise<boolean> {
    const mimeMatch = dataUriBase64.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,/i);
    const rawMime = mimeMatch ? mimeMatch[1].toLowerCase() : 'image/png';
    const mimetype = rawMime === 'image/jpg' ? 'image/jpeg' : rawMime;
    const cleanBase64 = dataUriBase64
      .replace(/^data:image\/[a-zA-Z0-9.+-]+;base64,/i, '')
      .replace(/\s+/g, '');
    const buffer = Buffer.from(cleanBase64, 'base64');

    return this.sendMessageWithFallback(
      phoneDigits,
      preferredJid,
      () => ({
        image: buffer,
        mimetype,
        caption,
      }),
      caption
    );
  }

  private resolveJid(phoneDigits: string, preferredJid?: string): string {
    if (preferredJid && preferredJid.includes('@')) {
      return preferredJid;
    }
    const clean = onlyDigits(phoneDigits);
    const fromMem = this.jidMap.get(clean);
    if (fromMem) return fromMem;
    const savedSession = this.repository.getSession(clean);
    if (savedSession.customerJid) return savedSession.customerJid;
    return `${clean}@s.whatsapp.net`;
  }

  private clearAuthFolder(): void {
    try {
      fs.rmSync(this.authDir, { recursive: true, force: true });
    } catch {
      // Ignora
    }
  }
}
