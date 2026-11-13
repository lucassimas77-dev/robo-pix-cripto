import dotenv from 'dotenv';
import type { SupportedProviderName } from '../types/domain.ts';

dotenv.config();

export type WhatsAppMode = 'simulator' | 'meta' | 'evolution';

export interface AppConfig {
  port: number;
  publicBaseUrl: string;
  cryptoProvider: SupportedProviderName;
  walletAddress: string;
  walletAsset: string;
  walletNetwork: string;
  pixExpirationMinutes: number;
  pixWarningBeforeMinutes: number;
  requirePayerDocument: boolean;
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
  pixgo: {
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

export function loadConfig(): AppConfig {
  const providerRaw = (process.env.CRYPTO_PROVIDER || 'mock').toLowerCase();
  const validProviders: SupportedProviderName[] = ['mock', 'depixapp', 'hodle', 'pixgo', 'noxpay'];
  const cryptoProvider: SupportedProviderName = validProviders.includes(providerRaw as SupportedProviderName)
    ? (providerRaw as SupportedProviderName)
    : 'mock';

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

  return {
    port: Number(process.env.PORT || 3000),
    publicBaseUrl: autoBaseUrl.replace(/\/+$/, ''),
    cryptoProvider,
    walletAddress: process.env.WALLET_ADDRESS || 'lq1qq_sua_carteira_liquid_autocustodia',
    walletAsset: process.env.WALLET_ASSET || 'DEPIX',
    walletNetwork: process.env.WALLET_NETWORK || 'LIQUID',
    pixExpirationMinutes: Math.max(5, Number(process.env.PIX_EXPIRATION_MINUTES || 15)),
    pixWarningBeforeMinutes: Math.max(1, Number(process.env.PIX_WARNING_BEFORE_MINUTES || 3)),
    // Por padrão FALSE: gera o Pix direto sem pedir CPF nem identificar ninguém no WhatsApp!
    requirePayerDocument: (process.env.REQUIRE_PAYER_DOCUMENT || 'false').toLowerCase() === 'true',
    whatsappMode,
    adminWhatsappPhone: (process.env.ADMIN_WHATSAPP_PHONE || '').replace(/\D/g, ''),
    depixapp: {
      apiUrl: (process.env.DEPIXAPP_API_URL || 'https://api.depixapp.com/api').replace(/\/+$/, ''),
      apiKey: process.env.DEPIXAPP_API_KEY || '',
      webhookSecret: process.env.DEPIXAPP_WEBHOOK_SECRET || 'dev_depixapp_secret',
    },
    hodle: {
      apiUrl: (process.env.HODLE_API_URL || 'https://api.hodle.com.br').replace(/\/+$/, ''),
      apiKey: process.env.HODLE_API_KEY || '',
      webhookSecret: process.env.HODLE_WEBHOOK_SECRET || 'dev_hodle_secret',
    },
    pixgo: {
      apiUrl: (process.env.PIXGO_API_URL || 'https://pixgo.org/api/v1').replace(/\/+$/, ''),
      apiKey: process.env.PIXGO_API_KEY || '',
      webhookSecret: process.env.PIXGO_WEBHOOK_SECRET || 'dev_pixgo_secret',
    },
    noxpay: {
      apiUrl: (process.env.NOXPAY_API_URL || 'https://api.noxpay.io/v2').replace(/\/+$/, ''),
      apiKey: process.env.NOXPAY_API_KEY || '',
      webhookSecret: process.env.NOXPAY_WEBHOOK_SECRET || 'dev_noxpay_secret',
    },
    metaWhatsapp: {
      token: process.env.META_WA_TOKEN || '',
      phoneNumberId: process.env.META_WA_PHONE_NUMBER_ID || '',
      verifyToken: process.env.META_WA_VERIFY_TOKEN || 'meu_token_secreto_webhook',
    },
    evolutionWhatsapp: {
      apiUrl: (process.env.EVOLUTION_API_URL || 'http://localhost:8080').replace(/\/+$/, ''),
      apiKey: process.env.EVOLUTION_API_KEY || '',
      instanceName: process.env.EVOLUTION_INSTANCE_NAME || 'pix_crypto_bot',
    },
  };
}
