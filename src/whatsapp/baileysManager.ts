import fs from 'node:fs';
import path from 'node:path';
import QRCode from 'qrcode';
import pino from 'pino';
import {
  DisconnectReason,
  fetchLatestBaileysVersion,
  makeWASocket,
  normalizeMessageContent,
  useMultiFileAuthState,
} from '@whiskeysockets/baileys';
import type { WASocket } from '@whiskeysockets/baileys';
import { OrderRepository } from '../database/orderRepository.ts';
import type { FilterMode } from '../types/domain.ts';
import {
  isCancelCommand,
  isExitCommand,
  isHelpCommand,
  isPaymentConfirmationMessage,
  isStatusQueryMessage,
  onlyDigits,
} from '../utils/cpfCnpjValidator.ts';

export type { FilterMode };

export interface BaileysStatusSnapshot {
  state: 'DISCONNECTED' | 'CONNECTING' | 'QR_READY' | 'CONNECTED';
  qrCodeDataUrl?: string;
  connectedPhone?: string;
  filterMode: FilterMode;
  allowedTestPhone: string;
  lastError?: string;
}

const MAX_UNSCANNED_QR_CYCLES = 3;
const MAX_JID_MAP_ENTRIES = 5_000;
const SESSION_FLOW_FRESHNESS_MS = 2 * 60 * 60 * 1000; // 2 horas
const RECENT_ORDER_CONTEXT_MS = 24 * 60 * 60 * 1000; // 24 horas para comandos pós-pagamento ("já paguei", "status")

export class BaileysDirectManager {
  private sock: WASocket | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private connectGeneration = 0;
  private state: BaileysStatusSnapshot['state'] = 'DISCONNECTED';
  private qrCodeDataUrl: string | undefined;
  private connectedPhone: string | undefined;
  private lastError: string | undefined;
  private filterMode: FilterMode = 'keyword_only';
  private allowedTestPhone = '';
  private intentionalStop = false;
  private hadOpenSession = false;
  private unscannedQrCount = 0;

  private readonly jidMap = new Map<string, string>();
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
    return this.getStatus();
  }

  public isConnected(): boolean {
    return this.state === 'CONNECTED' && this.sock !== null;
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private rememberJid(phoneDigits: string, jid: string): void {
    if (this.jidMap.has(phoneDigits)) {
      this.jidMap.delete(phoneDigits);
    } else if (this.jidMap.size >= MAX_JID_MAP_ENTRIES) {
      const oldestKey = this.jidMap.keys().next().value;
      if (oldestKey !== undefined) {
        this.jidMap.delete(oldestKey);
      }
    }
    this.jidMap.set(phoneDigits, jid);
  }

  public async startConnection(resetQrAttempts = true): Promise<BaileysStatusSnapshot> {
    if (this.state === 'CONNECTING' || this.state === 'QR_READY' || this.state === 'CONNECTED') {
      return this.getStatus();
    }

    const gen = ++this.connectGeneration;
    this.clearReconnectTimer();
    if (resetQrAttempts) {
      this.unscannedQrCount = 0;
    }

    this.intentionalStop = false;
    this.state = 'CONNECTING';
    this.lastError = undefined;

    try {
      fs.mkdirSync(this.authDir, { recursive: true });
      const { state: authState, saveCreds } = await useMultiFileAuthState(this.authDir);
      if (this.intentionalStop || gen !== this.connectGeneration) {
        return this.getStatus();
      }

      let version: [number, number, number] | undefined;
      try {
        const latest = await fetchLatestBaileysVersion();
        version = latest.version;
      } catch {
        // Fallback embutido
      }

      if (this.intentionalStop || gen !== this.connectGeneration) {
        return this.getStatus();
      }

      const logger = pino({ level: 'silent' });
      const sock = makeWASocket({
        ...(version ? { version } : {}),
        auth: authState,
        logger,
        printQRInTerminal: false,
        browser: ['Automacao Pix Cripto', 'Chrome', '1.0.0'],
        syncFullHistory: false,
      });

      this.sock = sock;

      sock.ev.on('creds.update', () => {
        if (this.intentionalStop || gen !== this.connectGeneration) return;
        Promise.resolve(saveCreds()).catch((err) => {
          console.error('[WhatsApp QR] Erro ao salvar credenciais:', err);
        });
      });

      sock.ev.on('connection.update', async (update) => {
        try {
          if (this.sock !== sock || gen !== this.connectGeneration) return;

          const { connection, lastDisconnect, qr } = update;

          if (qr) {
            this.unscannedQrCount++;
            if (!this.hadOpenSession && this.unscannedQrCount > MAX_UNSCANNED_QR_CYCLES) {
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
              return;
            }
            const dataUrl = await QRCode.toDataURL(qr, { width: 280, margin: 2 });
            if (this.sock !== sock || gen !== this.connectGeneration || this.intentionalStop) {
              return;
            }
            this.qrCodeDataUrl = dataUrl;
            this.state = 'QR_READY';
          }

          if (connection === 'open') {
            this.hadOpenSession = true;
            this.unscannedQrCount = 0;
            this.state = 'CONNECTED';
            this.qrCodeDataUrl = undefined;
            this.lastError = undefined;
            const rawId = sock.user?.id || '';
            this.connectedPhone = onlyDigits(
              rawId.split('@')[0]?.split(':')[0]?.split('_')[0] || ''
            );
            console.log(`[WhatsApp QR] Conectado com sucesso! Número: +${this.connectedPhone}`);
          }

          if (connection === 'close') {
            this.sock = null;
            this.qrCodeDataUrl = undefined;
            const statusCode = (
              lastDisconnect?.error as { output?: { statusCode?: number } } | undefined
            )?.output?.statusCode;

            if (statusCode === DisconnectReason.loggedOut) {
              this.clearAuthFolder();
              this.hadOpenSession = false;
              this.state = 'DISCONNECTED';
              this.connectedPhone = undefined;
              this.lastError = 'Sessão desconectada pelo celular. Gere um novo QR Code.';
            } else if (!this.intentionalStop && gen === this.connectGeneration) {
              this.state = 'DISCONNECTED';
              this.clearReconnectTimer();
              this.reconnectTimer = setTimeout(() => {
                this.reconnectTimer = null;
                if (!this.intentionalStop && gen === this.connectGeneration) {
                  this.startConnection(false).catch((err) => {
                    console.error('[WhatsApp QR] Falha ao reconectar sessão:', err);
                  });
                }
              }, 3000);
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
        if (type !== 'notify') return;

        for (const msg of messages) {
          try {
            if (!msg.message || msg.key.fromMe) continue;
            const remoteJid = msg.key.remoteJid || '';
            if (
              !remoteJid ||
              remoteJid.endsWith('@g.us') ||
              remoteJid.endsWith('@broadcast') ||
              remoteJid.endsWith('@newsletter') ||
              remoteJid.endsWith('@bot')
            ) {
              continue;
            }

            const normalized = normalizeMessageContent(msg.message);
            if (!normalized) continue;

            const text = (
              normalized.conversation ||
              normalized.extendedTextMessage?.text ||
              normalized.imageMessage?.caption ||
              normalized.videoMessage?.caption ||
              normalized.documentMessage?.caption ||
              normalized.documentWithCaptionMessage?.message?.documentMessage?.caption ||
              ''
            ).trim();

            if (!text) continue;

            const altJid = (msg.key as Record<string, unknown>).remoteJidAlt
              ? String((msg.key as Record<string, unknown>).remoteJidAlt)
              : '';
            const bestJidForDigits = remoteJid.endsWith('@s.whatsapp.net')
              ? remoteJid
              : altJid || remoteJid;
            const userPart = bestJidForDigits.split('@')[0]?.split(':')[0]?.split('_')[0] || '';
            const senderDigits = onlyDigits(userPart);
            if (senderDigits.length < 8) continue;

            this.rememberJid(senderDigits, remoteJid);

            if (this.allowedTestPhone) {
              // Fail-closed: se o filtro está preenchido mas tem menos de 8 dígitos válidos, bloqueia tudo!
              if (this.allowedTestPhone.length < 8) {
                continue;
              }
              const last8Allowed = this.allowedTestPhone.slice(-8);
              const last8Sender = senderDigits.slice(-8);
              if (last8Allowed !== last8Sender) {
                continue;
              }
            }

            if (this.filterMode === 'keyword_only') {
              const session = this.repository.getSession(senderDigits);
              const activeOrder = this.repository.findActivePendingOrderByPhone(senderDigits);
              const sessionAgeMs = Date.now() - new Date(session.updatedAt).getTime();
              const isFreshSession =
                session.stage !== 'IDLE' &&
                Number.isFinite(sessionAgeMs) &&
                sessionAgeMs < SESSION_FLOW_FRESHNESS_MS;

              const recentOrder = this.repository.findMostRecentOrderByPhone(senderDigits);
              const hasRecentOrderContext =
                recentOrder !== null &&
                Date.now() - new Date(recentOrder.createdAt).getTime() < RECENT_ORDER_CONTEXT_MS;

              const isPostOrderFollowUp =
                hasRecentOrderContext &&
                (isPaymentConfirmationMessage(text) ||
                  isStatusQueryMessage(text) ||
                  isCancelCommand(text) ||
                  isExitCommand(text) ||
                  isHelpCommand(text));

              const isAlreadyInFlow =
                isFreshSession || activeOrder !== null || isPostOrderFollowUp;
              const hasPixKeyword =
                text.length <= 2_000 &&
                /\bpix\b|pagar|pagamento|chave[ \t]*pix|gerar[ \t]*pix|mand[ae][ \t]*(?:o[ \t]*)?pix|comprovante/i.test(
                  text
                );

              if (!isAlreadyInFlow && !hasPixKeyword) {
                continue;
              }
            }

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
          }
        }
      });
    } catch (err) {
      if (gen === this.connectGeneration && !this.intentionalStop) {
        this.state = 'DISCONNECTED';
        this.lastError = err instanceof Error ? err.message : String(err);
      }
    }

    return this.getStatus();
  }

  public async disconnect(wipeSession = false): Promise<BaileysStatusSnapshot> {
    this.connectGeneration++;
    this.intentionalStop = true;
    this.clearReconnectTimer();
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
    this.qrCodeDataUrl = undefined;
    this.state = 'DISCONNECTED';
    return this.getStatus();
  }

  public async sendText(
    phoneDigits: string,
    text: string,
    preferredJid?: string
  ): Promise<boolean> {
    if (!this.sock || this.state !== 'CONNECTED') return false;
    try {
      const targetJid = this.resolveJid(phoneDigits, preferredJid);
      await this.sock.sendMessage(targetJid, { text });
      return true;
    } catch (err) {
      console.error('[WhatsApp QR] Erro ao enviar mensagem de texto:', err);
      return false;
    }
  }

  public async sendImageWithCaption(
    phoneDigits: string,
    dataUriBase64: string,
    caption: string,
    preferredJid?: string
  ): Promise<boolean> {
    if (!this.sock || this.state !== 'CONNECTED') return false;
    try {
      const targetJid = this.resolveJid(phoneDigits, preferredJid);
      const cleanBase64 = dataUriBase64.replace(/^data:image\/\w+;base64,/, '');
      const buffer = Buffer.from(cleanBase64, 'base64');
      await this.sock.sendMessage(targetJid, {
        image: buffer,
        mimetype: 'image/png',
        caption,
      });
      return true;
    } catch (err) {
      console.error('[WhatsApp QR] Erro ao enviar imagem QR:', err);
      return false;
    }
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
