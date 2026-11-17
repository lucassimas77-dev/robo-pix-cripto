import type { AppConfig } from '../config/env.ts';
import { OrderRepository } from '../database/orderRepository.ts';
import type { IWhatsAppGateway } from '../types/domain.ts';
import { onlyDigits } from '../utils/cpfCnpjValidator.ts';
import type { BaileysDirectManager } from './baileysManager.ts';

const FETCH_TIMEOUT_MS = 15_000;

export class UnifiedWhatsAppGateway implements IWhatsAppGateway {
  private readonly config: AppConfig;
  private readonly repository: OrderRepository;
  private readonly baileys?: BaileysDirectManager;

  constructor(config: AppConfig, repository: OrderRepository, baileys?: BaileysDirectManager) {
    this.config = config;
    this.repository = repository;
    this.baileys = baileys;
  }

  public async sendText(rawPhone: string, text: string, preferredJid?: string): Promise<void> {
    const phone = onlyDigits(rawPhone);

    this.repository.logMessage({
      phone,
      direction: 'OUTBOUND',
      type: 'TEXT',
      body: text,
      createdAt: new Date().toISOString(),
    });

    if (this.baileys?.isConnected()) {
      await this.baileys.sendText(phone, text, preferredJid);
      return;
    }

    if (this.config.whatsappMode === 'meta') {
      await this.sendViaMetaText(phone, text);
    } else if (this.config.whatsappMode === 'evolution') {
      await this.sendViaEvolutionText(phone, text);
    }
  }

  public async sendPixCharge(params: {
    phone: string;
    preferredJid?: string;
    summaryText: string;
    pixCopyPaste: string;
    qrCodeBase64?: string;
    qrCodeUrl?: string;
  }): Promise<void> {
    const phone = onlyDigits(params.phone);

    this.repository.logMessage({
      phone,
      direction: 'OUTBOUND',
      type: 'IMAGE',
      body: params.summaryText,
      mediaBase64: params.qrCodeBase64,
      mediaUrl: params.qrCodeUrl,
      createdAt: new Date().toISOString(),
    });

    this.repository.logMessage({
      phone,
      direction: 'OUTBOUND',
      type: 'PIX_CODE',
      body: params.pixCopyPaste,
      createdAt: new Date().toISOString(),
    });

    if (this.baileys?.isConnected()) {
      if (params.qrCodeBase64) {
        await this.baileys.sendImageWithCaption(
          phone,
          params.qrCodeBase64,
          params.summaryText,
          params.preferredJid
        );
      } else {
        await this.baileys.sendText(phone, params.summaryText, params.preferredJid);
      }
      await this.baileys.sendText(phone, params.pixCopyPaste, params.preferredJid);
      return;
    }

    if (this.config.whatsappMode === 'meta') {
      await this.sendViaMetaText(phone, params.summaryText);
      if (params.qrCodeUrl) {
        await this.sendViaMetaImage(phone, params.qrCodeUrl, 'Escaneie o QR Code acima');
      }
      await this.sendViaMetaText(phone, params.pixCopyPaste);
    } else if (this.config.whatsappMode === 'evolution') {
      if (params.qrCodeBase64) {
        await this.sendViaEvolutionMedia(phone, params.qrCodeBase64, params.summaryText);
      } else {
        await this.sendViaEvolutionText(phone, params.summaryText);
      }
      await this.sendViaEvolutionText(phone, params.pixCopyPaste);
    }
  }

  private async sendViaMetaText(phone: string, body: string): Promise<void> {
    const { token, phoneNumberId } = this.config.metaWhatsapp;
    if (!token || !phoneNumberId) return;

    try {
      const res = await fetch(`https://graph.facebook.com/v21.0/${phoneNumberId}/messages`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          recipient_type: 'individual',
          to: phone,
          type: 'text',
          text: { preview_url: false, body },
        }),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });

      if (!res.ok) {
        const err = await res.text();
        console.error(`[WhatsApp Meta] Erro HTTP ${res.status}: ${err}`);
      }
    } catch (err) {
      console.error('[WhatsApp Meta] Falha de transporte:', err);
    }
  }

  private async sendViaMetaImage(phone: string, imageUrl: string, caption: string): Promise<void> {
    const { token, phoneNumberId } = this.config.metaWhatsapp;
    if (!token || !phoneNumberId) return;

    try {
      await fetch(`https://graph.facebook.com/v21.0/${phoneNumberId}/messages`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          recipient_type: 'individual',
          to: phone,
          type: 'image',
          image: { link: imageUrl, caption },
        }),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch (err) {
      console.error('[WhatsApp Meta] Falha de transporte imagem:', err);
    }
  }

  private async sendViaEvolutionText(phone: string, text: string): Promise<void> {
    const { apiUrl, apiKey, instanceName } = this.config.evolutionWhatsapp;
    if (!apiKey) return;

    try {
      const res = await fetch(`${apiUrl}/message/sendText/${encodeURIComponent(instanceName)}`, {
        method: 'POST',
        headers: {
          apikey: apiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ number: phone, text }),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });

      if (!res.ok) {
        const err = await res.text();
        console.error(`[WhatsApp Evolution] Erro HTTP ${res.status}: ${err}`);
      }
    } catch (err) {
      console.error('[WhatsApp Evolution] Falha de transporte texto:', err);
    }
  }

  private async sendViaEvolutionMedia(
    phone: string,
    dataUriBase64: string,
    caption: string
  ): Promise<void> {
    const { apiUrl, apiKey, instanceName } = this.config.evolutionWhatsapp;
    if (!apiKey) return;

    const mimeMatch = dataUriBase64.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,/i);
    const rawMime = mimeMatch ? mimeMatch[1].toLowerCase() : 'image/png';
    const mimetype = rawMime === 'image/jpg' ? 'image/jpeg' : rawMime;
    const ext = mimetype === 'image/jpeg' ? 'jpg' : mimetype === 'image/webp' ? 'webp' : 'png';
    const cleanBase64 = dataUriBase64
      .replace(/^data:image\/[a-zA-Z0-9.+-]+;base64,/i, '')
      .replace(/\s+/g, '');

    try {
      await fetch(`${apiUrl}/message/sendMedia/${encodeURIComponent(instanceName)}`, {
        method: 'POST',
        headers: {
          apikey: apiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          number: phone,
          mediatype: 'image',
          mimetype,
          caption,
          media: cleanBase64,
          fileName: `qrcode-pix.${ext}`,
        }),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch (err) {
      console.error('[WhatsApp Evolution] Falha de transporte mídia:', err);
    }
  }
}
