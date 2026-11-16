import type { AppConfig } from '../config/env.ts';
import type { IPixCryptoProvider, RuntimeAccountSettings } from '../types/domain.ts';
import { DePixAppProvider } from './depixAppProvider.ts';
import { HodleProvider } from './hodleProvider.ts';
import { MockProvider } from './mockProvider.ts';
import { NoxPayProvider } from './noxPayProvider.ts';

export function createCryptoProvider(
  config: AppConfig,
  runtimeOverride?: RuntimeAccountSettings
): IPixCryptoProvider {
  const providerName = runtimeOverride?.provider ?? config.cryptoProvider;
  const customApiKey = runtimeOverride?.apiKey?.trim();
  const customSecret = runtimeOverride?.webhookSecret?.trim();

  switch (providerName) {
    case 'depixapp':
      return new DePixAppProvider({
        apiUrl: config.depixapp.apiUrl,
        apiKey: customApiKey || config.depixapp.apiKey,
        webhookSecret: customSecret || config.depixapp.webhookSecret,
      });
    case 'hodle':
      return new HodleProvider({
        apiUrl: config.hodle.apiUrl,
        apiKey: customApiKey || config.hodle.apiKey,
        webhookSecret: customSecret || config.hodle.webhookSecret,
      });
    case 'noxpay':
      return new NoxPayProvider({
        apiUrl: config.noxpay.apiUrl,
        apiKey: customApiKey || config.noxpay.apiKey,
        webhookSecret: customSecret || config.noxpay.webhookSecret,
      });
    case 'mock':
    default:
      return new MockProvider({
        webhookSecret: customSecret,
      });
  }
}
