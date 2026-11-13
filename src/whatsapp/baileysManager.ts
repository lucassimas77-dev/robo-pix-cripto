import fs from 'node:fs';
import path from 'node:path';
import QRCode from 'qrcode';
import pino from 'pino';
import {
  DisconnectReason,
  fetchLatestBaileysVersion,
  makeWASocket,
  useMultiFileAuthState,
} from '@whiskeysockets/baileys';
import type { WASocket } from '@whiskeysockets/baileys';
import { OrderRepository } from '../database/orderRepository.ts';
import { onlyDigits } from '../utils/cpfCnpjValidator.ts';

export type FilterMode = 'keyword_only' | 'all';

export interface BaileysStatusSnapshot {
  state: 'DISCONNECTED' | 'CONNECTING' | 'QR_READY' | 'CONNECTED';
  qrCodeDataUrl?: string;
  connectedPhone?: string;
  filterMode: FilterMode;
  allowedTestPhone: string;
  lastError?: string;
}

/**
 * Gerenciador embutido de conexão direta com WhatsApp via QR Code (estilo WhatsApp Web).
 * Não exige Docker externo nem conta aprovada na Meta Business.
 * Possui travas inteligentes para não interferir em conversas pessoais durante testes!
 */
export class BaileysDirectManager {
  private sock: WASocket | null = null;
  private state: BaileysStatusSnapshot['state'] = 'DISCONNECTED';
  private qrCodeDataUrl: string | undefined;
  private connectedPhone: string | undefined;
  private lastError: string | undefined;
  private filterMode: FilterMode = 'keyword_only';
  private allowedTestPhone = '';
  private intentionalStop = false;

  // Mapeia o identificador numérico limpo para o JID exato do WhatsApp (@s.whatsapp.net ou @lid)
  private readonly jidMap = new Map<string, string>();
  private readonly authDir: string;
  private readonly repository: OrderRepository;
  private onIncomingTextCallback?: (params: {
    phone: string;
    text: string;
    customerName?: string;
  }) => Promise<void>;

  constructor(
    repository: OrderRepository,
    authDir = path.resolve(process.cwd(), 'data', 'wa_auth')
  ) {
    this.repository = repository;
    this.authDir = authDir;
  }

  public setIncomingHandler(
    handler: (params: { phone: string; text: string; customerName?: string }) => Promise<void>
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

  public async startConnection(): Promise<BaileysStatusSnapshot> {
    if (this.state === 'CONNECTING' || this.state === 'QR_READY' || this.state === 'CONNECTED') {
      return this.getStatus();
    }

    this.intentionalStop = false;
    this.state = 'CONNECTING';
    this.lastError = undefined;
    fs.mkdirSync(this.authDir, { recursive: true });

    try {
      const { state: authState, saveCreds } = await useMultiFileAuthState(this.authDir);
      let version: [number, number, number] | undefined;
      try {
        const latest = await fetchLatestBaileysVersion();
        version = latest.version;
      } catch {
        // Usa versão padrão embutida caso offline temporário
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

      sock.ev.on('creds.update', saveCreds);

      sock.ev.on('connection.update', async (update) => {
        const { connection, lastDisconnect, qr } = update;

        if (qr) {
          this.qrCodeDataUrl = await QRCode.toDataURL(qr, { width: 280, margin: 2 });
          this.state = 'QR_READY';
        }

        if (connection === 'open') {
          this.state = 'CONNECTED';
          this.qrCodeDataUrl = undefined;
          this.lastError = undefined;
          const rawId = sock.user?.id || '';
          this.connectedPhone = onlyDigits(rawId.split(':')[0] || rawId.split('@')[0] || '');
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
            this.state = 'DISCONNECTED';
            this.connectedPhone = undefined;
            this.lastError = 'Sessão desconectada pelo celular. Gere um novo QR Code.';
          } else if (!this.intentionalStop) {
            this.state = 'DISCONNECTED';
            // Reconexão automática suave após queda de rede
            setTimeout(() => {
              if (!this.intentionalStop) {
                void this.startConnection();
              }
            }, 3000);
          } else {
            this.state = 'DISCONNECTED';
          }
        }
      });

      sock.ev.on('messages.upsert', async ({ messages, type }) => {
        if (type !== 'notify') return;

        for (const msg of messages) {
          if (!msg.message || msg.key.fromMe) continue;
          const remoteJid = msg.key.remoteJid || '';
          if (!remoteJid || remoteJid.endsWith('@g.us') || remoteJid === 'status@broadcast') {
            continue; // Ignora grupos e status!
          }

          // Extrai texto simples ou resposta estendida
          const text = (
            msg.message.conversation ||
            msg.message.extendedTextMessage?.text ||
            ''
          ).trim();

          if (!text) continue;

          // Identifica telefone/chave limpa e guarda o JID real para resposta
          const altJid = (msg.key as Record<string, unknown>).remoteJidAlt
            ? String((msg.key as Record<string, unknown>).remoteJidAlt)
            : '';
          const bestJidForDigits = remoteJid.endsWith('@s.whatsapp.net')
            ? remoteJid
            : altJid || remoteJid;
          const senderDigits = onlyDigits(bestJidForDigits.split('@')[0] || '');
          if (!senderDigits) continue;

          this.jidMap.set(senderDigits, remoteJid);

          // 1. Trava opcional de Telefone de Teste (ex: responder apenas ao amigo!)
          if (this.allowedTestPhone) {
            const last8Allowed = this.allowedTestPhone.slice(-8);
            const last8Sender = senderDigits.slice(-8);
            if (last8Allowed.length >= 8 && last8Allowed !== last8Sender) {
              continue; // Ignora qualquer outro contato!
            }
          }

          // 2. Trava de Palavra-Chave Inteligente (não atrapalha conversas normais!)
          if (this.filterMode === 'keyword_only') {
            const session = this.repository.getSession(senderDigits);
            const activeOrder = this.repository.findActivePendingOrderByPhone(senderDigits);
            const isAlreadyInFlow = session.stage !== 'IDLE' || activeOrder !== null;
            const hasPixKeyword =
              /\bpix\b|pagar|pagamento|chave\s*pix|gerar\s*pix|mand[ae]\s*o?\s*pix/i.test(text);

            if (!isAlreadyInFlow && !hasPixKeyword) {
              continue; // Conversa pessoal comum: o robô permanece 100% invisível!
            }
          }

          if (this.onIncomingTextCallback) {
            await this.onIncomingTextCallback({
              phone: senderDigits,
              text,
              customerName: msg.pushName || undefined,
            });
          }
        }
      });
    } catch (err) {
      this.state = 'DISCONNECTED';
      this.lastError = err instanceof Error ? err.message : String(err);
    }

    return this.getStatus();
  }

  public async disconnect(wipeSession = false): Promise<BaileysStatusSnapshot> {
    this.intentionalStop = true;
    if (this.sock) {
      try {
        if (wipeSession) {
          await this.sock.logout();
        } else {
          this.sock.end(undefined);
        }
      } catch {
        // Ignora erro de fechamento de socket
      }
      this.sock = null;
    }
    if (wipeSession) {
      this.clearAuthFolder();
      this.connectedPhone = undefined;
    }
    this.qrCodeDataUrl = undefined;
    this.state = 'DISCONNECTED';
    return this.getStatus();
  }

  public async sendText(phoneDigits: string, text: string): Promise<boolean> {
    if (!this.sock || this.state !== 'CONNECTED') return false;
    const targetJid = this.resolveJid(phoneDigits);
    await this.sock.sendMessage(targetJid, { text });
    return true;
  }

  public async sendImageWithCaption(
    phoneDigits: string,
    dataUriBase64: string,
    caption: string
  ): Promise<boolean> {
    if (!this.sock || this.state !== 'CONNECTED') return false;
    const targetJid = this.resolveJid(phoneDigits);
    const cleanBase64 = dataUriBase64.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(cleanBase64, 'base64');
    await this.sock.sendMessage(targetJid, {
      image: buffer,
      caption,
    });
    return true;
  }

  private resolveJid(phoneDigits: string): string {
    const clean = onlyDigits(phoneDigits);
    return this.jidMap.get(clean) || `${clean}@s.whatsapp.net`;
  }

  private clearAuthFolder(): void {
    try {
      fs.rmSync(this.authDir, { recursive: true, force: true });
    } catch {
      // Ignora caso não exista
    }
  }
}
