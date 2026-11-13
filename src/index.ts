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
  const repository = new OrderRepository();

  // Carrega configurações salvas pela tela web (se o usuário ou amigo já tiver salvado a conta dele)
  const savedAccount = repository.getRuntimeSettings({
    provider: baseConfig.cryptoProvider,
    apiKey: '',
    webhookSecret: '',
    walletAddress: baseConfig.walletAddress,
    walletAsset: baseConfig.walletAsset,
    walletNetwork: baseConfig.walletNetwork,
    pixExpirationMinutes: baseConfig.pixExpirationMinutes,
    adminWhatsappPhone: baseConfig.adminWhatsappPhone,
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
  const baileysManager = new BaileysDirectManager(repository);
  const whatsappGateway = new UnifiedWhatsAppGateway(activeConfig, repository, baileysManager);
  const engine = new ConversationEngine(activeConfig, repository, cryptoProvider, whatsappGateway);

  baileysManager.setIncomingHandler(async ({ phone, text, customerName }) => {
    await engine.handleIncomingMessage({ phone, text, customerName });
  });

  const expirationWatcher = new ExpirationWatcher(
    repository,
    whatsappGateway,
    activeConfig.pixWarningBeforeMinutes,
    engine
  );

  expirationWatcher.start(8_000);

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

  const shutdown = () => {
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
