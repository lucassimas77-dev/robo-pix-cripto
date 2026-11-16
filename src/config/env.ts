import path from 'node:path';
import dotenv from 'dotenv';
import type { SupportedProviderName } from '../types/domain.ts';

dotenv.config();

export type WhatsAppMode = 'simulator' | 'meta' | 'evolution';

export interface AppConfig {
  port: number;
  dataDir: string;
  publicBaseUrl: string;
  adminPassword: string;
  cryptoProvider: SupportedProviderName;
  walletAddress: string;
  walletAsset: string;
  walletNetwork: string;
  pixExpirationMinutes: number;
  pixWarningBeforeMinutes: number;
  whatsappMode: WhatsAppMode;
  adminWhatsappPhone: string;
  depixapp: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
  };
  hodle: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
  };
  noxpay: {
    apiUrl: string;
    apiKey: string;
    webhookSecret: string;
  };
  metaWhatsapp: {
    token: string;
    phoneNumberId: string;
    verifyToken: string;
  };
  evolutionWhatsapp: {
    apiUrl: string;
    apiKey: string;
    instanceName: string;
  };
}

export const SUPPORTED_PROVIDERS: SupportedProviderName[] = [
  'mock',
  'depixapp',
  'hodle',
  'noxpay',
];

export function loadConfig(): AppConfig {
  const providerRaw = (process.env.CRYPTO_PROVIDER || 'depixapp').toLowerCase();
  const cryptoProvider: SupportedProviderName = SUPPORTED_PROVIDERS.includes(
    providerRaw as SupportedProviderName
  )
    ? (providerRaw as SupportedProviderName)
    : 'depixapp';

  const waModeRaw = (process.env.WHATSAPP_MODE || 'simulator').toLowerCase();
  const validWaModes: WhatsAppMode[] = ['simulator', 'meta', 'evolution'];
  const whatsappMode: WhatsAppMode = validWaModes.includes(waModeRaw as WhatsAppMode)
    ? (waModeRaw as WhatsAppMode)
    : 'simulator';

  const autoBaseUrl =
    process.env.PUBLIC_BASE_URL ||
    process.env.RENDER_EXTERNAL_URL ||
    (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '') ||
    'http://localhost:3000';

  const dataDir = process.env.DATA_DIR
    ? path.resolve(process.env.DATA_DIR)
    : path.resolve(process.cwd(), 'data');

  return {
    port: Number(process.env.PORT || 3000),
    dataDir,
    publicBaseUrl: autoBaseUrl.replace(/\/+$/, ''),
    adminPassword: (process.env.ADMIN_PASSWORD || '').trim(),
    cryptoProvider,
    walletAddress: (process.env.WALLET_ADDRESS || '').trim(),
    walletAsset: (process.env.WALLET_ASSET || 'DEPIX').trim().toUpperCase(),
    walletNetwork: (process.env.WALLET_NETWORK || 'LIQUID').trim().toUpperCase(),
    pixExpirationMinutes: Math.min(20, Math.max(5, Number(process.env.PIX_EXPIRATION_MINUTES || 15))),
    pixWarningBeforeMinutes: Math.max(1, Number(process.env.PIX_WARNING_BEFORE_MINUTES || 3)),
    whatsappMode,
    adminWhatsappPhone: (process.env.ADMIN_WHATSAPP_PHONE || '').replace(/\D/g, ''),
    // NUNCA usa segredo de webhook hardcoded! String vazia rejeita webhooks sem segredo configurado.
    depixapp: {
      apiUrl: (process.env.DEPIXAPP_API_URL || 'https://api.depixapp.com/api').replace(/\/+$/, ''),
      apiKey: (process.env.DEPIXAPP_API_KEY || '').trim(),
      webhookSecret: (process.env.DEPIXAPP_WEBHOOK_SECRET || '').trim(),
    },
    hodle: {
      apiUrl: (process.env.HODLE_API_URL || 'https://api.hodle.com.br').replace(/\/+$/, ''),
      apiKey: (process.env.HODLE_API_KEY || '').trim(),
      webhookSecret: (process.env.HODLE_WEBHOOK_SECRET || '').trim(),
    },
    noxpay: {
      apiUrl: (process.env.NOXPAY_API_URL || 'https://api.noxpay.io/v2').replace(/\/+$/, ''),
      apiKey: (process.env.NOXPAY_API_KEY || '').trim(),
      webhookSecret: (process.env.NOXPAY_WEBHOOK_SECRET || '').trim(),
    },
    metaWhatsapp: {
      token: (process.env.META_WA_TOKEN || '').trim(),
      phoneNumberId: (process.env.META_WA_PHONE_NUMBER_ID || '').trim(),
      verifyToken: (process.env.META_WA_VERIFY_TOKEN || '').trim(),
    },
    evolutionWhatsapp: {
      apiUrl: (process.env.EVOLUTION_API_URL || 'http://localhost:8080').replace(/\/+$/, ''),
      apiKey: (process.env.EVOLUTION_API_KEY || '').trim(),
      instanceName: (process.env.EVOLUTION_INSTANCE_NAME || 'pix_crypto_bot').trim(),
    },
  };
}
