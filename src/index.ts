import path from 'node:path';
import { loadConfig } from './config/env.ts';
import { OrderRepository } from './database/orderRepository.ts';
import { createCryptoProvider } from './providers/providerFactory.ts';
import { createAppHttpServer } from './server/httpServer.ts';
import { ConversationEngine } from './services/conversationEngine.ts';
import { ExpirationWatcher } from './services/expirationWatcher.ts';
import { BaileysDirectManager } from './whatsapp/baileysManager.ts';
import { UnifiedWhatsAppGateway } from './whatsapp/whatsappGateway.ts';

async function bootstrap(): Promise<void> {
  const baseConfig = loadConfig();
  const dbPath = path.join(baseConfig.dataDir, 'automation.sqlite');
  const waAuthDir = path.join(baseConfig.dataDir, 'wa_auth');

  const repository = new OrderRepository(dbPath);

  const savedAccount = repository.getRuntimeSettings({
    provider: baseConfig.cryptoProvider,
    apiKey: '',
    webhookSecret: '',
    walletAddress: baseConfig.walletAddress,
    walletAsset: baseConfig.walletAsset,
    walletNetwork: baseConfig.walletNetwork,
    pixExpirationMinutes: baseConfig.pixExpirationMinutes,
    adminWhatsappPhone: baseConfig.adminWhatsappPhone,
    waFilterMode: 'keyword_only',
    waAllowedTestPhone: '',
  });

  const activeConfig = {
    ...baseConfig,
    cryptoProvider: savedAccount.provider,
    walletAddress: savedAccount.walletAddress,
    walletAsset: savedAccount.walletAsset,
    walletNetwork: savedAccount.walletNetwork,
    pixExpirationMinutes: savedAccount.pixExpirationMinutes,
    adminWhatsappPhone: savedAccount.adminWhatsappPhone,
  };

  const cryptoProvider = createCryptoProvider(activeConfig, savedAccount);
  const baileysManager = new BaileysDirectManager(repository, waAuthDir, {
    filterMode: savedAccount.waFilterMode,
    allowedTestPhone: savedAccount.waAllowedTestPhone,
  });
  const whatsappGateway = new UnifiedWhatsAppGateway(activeConfig, repository, baileysManager);
  const engine = new ConversationEngine(activeConfig, repository, cryptoProvider, whatsappGateway);

  baileysManager.setIncomingHandler(async ({ phone, customerJid, text, customerName }) => {
    await engine.handleIncomingMessage({ phone, customerJid, text, customerName });
  });

  const expirationWatcher = new ExpirationWatcher(
    repository,
    whatsappGateway,
    activeConfig.pixWarningBeforeMinutes,
    engine
  );

  // Intervalo de 15s respeita folgadamente o rate limit de 30 req/min por conta da DePix App
  expirationWatcher.start(15_000);

  const server = createAppHttpServer({
    config: activeConfig,
    repository,
    engine,
    baileys: baileysManager,
  });

  server.listen(activeConfig.port, '0.0.0.0', () => {
    console.log('===================================================================');
    console.log('⚡ ROBÔ PIX -> CARTEIRA CRIPTO PRONTO E NO AR!');
    console.log(`🌐 Acesse o Painel: http://localhost:${activeConfig.port}`);
    console.log('===================================================================');
  });

  const externalKeepAliveUrl = process.env.RENDER_EXTERNAL_URL;
  let keepAliveTimer: NodeJS.Timeout | undefined;
  if (externalKeepAliveUrl) {
    const cleanUrl = externalKeepAliveUrl.replace(/\/+$/, '');
    keepAliveTimer = setInterval(() => {
      fetch(`${cleanUrl}/health`, { signal: AbortSignal.timeout(10_000) }).catch(() => {});
    }, 10 * 60 * 1000);
    keepAliveTimer.unref();
  }

  const shutdown = () => {
    if (keepAliveTimer) clearInterval(keepAliveTimer);
    expirationWatcher.stop();
    void baileysManager.disconnect(false);
    server.close(() => {
      repository.close();
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

bootstrap().catch((err) => {
  console.error('Falha fatal ao iniciar:', err);
  process.exit(1);
});
