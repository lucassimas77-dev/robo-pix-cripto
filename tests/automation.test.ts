import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadConfig } from '../src/config/env.ts';
import type { AppConfig } from '../src/config/env.ts';
import { OrderRepository } from '../src/database/orderRepository.ts';
import { DePixAppProvider } from '../src/providers/depixAppProvider.ts';
import { HodleProvider } from '../src/providers/hodleProvider.ts';
import { MockProvider } from '../src/providers/mockProvider.ts';
import { NoxPayProvider } from '../src/providers/noxPayProvider.ts';
import { ConversationEngine } from '../src/services/conversationEngine.ts';
import { ExpirationWatcher } from '../src/services/expirationWatcher.ts';
import { parseBrlAmountFromText } from '../src/utils/cpfCnpjValidator.ts';
import { UnifiedWhatsAppGateway } from '../src/whatsapp/whatsappGateway.ts';

function createPrivacyTestSetup() {
  const config: AppConfig = {
    ...loadConfig(),
    cryptoProvider: 'mock',
    whatsappMode: 'simulator',
    walletAddress: 'lq1qq_carteira_liquid_autocustodia_privada',
    walletAsset: 'DEPIX',
    walletNetwork: 'LIQUID',
    pixExpirationMinutes: 15,
    pixWarningBeforeMinutes: 3,
    requirePayerDocument: false, // ZERO IDENTIFICAÇÃO!
    adminWhatsappPhone: '5511900000000',
  };

  const repository = new OrderRepository(':memory:');
  const provider = new MockProvider({ requiresPayerDocument: false });
  const whatsapp = new UnifiedWhatsAppGateway(config, repository);
  const engine = new ConversationEngine(config, repository, provider, whatsapp);
  const watcher = new ExpirationWatcher(repository, whatsapp, config.pixWarningBeforeMinutes);

  return { config, repository, provider, whatsapp, engine, watcher };
}

test('Fluxo Privado (Zero Identificação): Cliente envia valor no WhatsApp e já recebe a chave Pix na hora sem pedir CPF nem nome', async () => {
  const { repository, engine } = createPrivacyTestSetup();
  const clientPhone = '5511988887777';

  // 1. Cliente manda apenas "Me manda um Pix de R$ 250,00" -> Sistema NÃO pede CPF nem nome, já entrega o Pix!
  await engine.handleIncomingMessage({
    phone: clientPhone,
    text: 'Me manda um Pix de R$ 250,00',
  });

  const orders = repository.listRecentOrders();
  assert.equal(orders.length, 1);
  const createdOrder = orders[0];
  assert.equal(createdOrder.amountBrl, 250);
  assert.equal(createdOrder.payerDocument, undefined);
  assert.equal(createdOrder.status, 'PENDING');
  assert.ok(createdOrder.pixCopyPaste.startsWith('000201'));
  assert.ok(createdOrder.pixQrCodeBase64?.startsWith('data:image/png;base64,'));

  // Verifica que enviou o QR Code + a mensagem isolada contendo apenas o Pix Copia e Cola puro
  const msgs = repository.listMessages(clientPhone);
  assert.equal(msgs.length, 3); // 1 INBOUND + 1 IMAGE (resumo/QR) + 1 PIX_CODE (código puro)
  assert.equal(msgs[2].type, 'PIX_CODE');
  assert.equal(msgs[2].body, createdOrder.pixCopyPaste);

  // 2. Pagamento cai na liquidante -> Webhook confirma e liquida direto na carteira privada!
  const settlement = await engine.handleSettlementWebhook({
    provider: 'mock',
    externalId: createdOrder.externalId,
    newStatus: 'SETTLED_CRYPTO',
    txHash: 'tx_liquid_confidencial_998877',
    cryptoAmount: 245,
    rawEventName: 'MOCK_SETTLED_CRYPTO',
  });

  assert.equal(settlement.matched, true);
  assert.equal(settlement.changed, true);
  assert.equal(settlement.order?.status, 'SETTLED_CRYPTO');

  // Admin recebe alerta da liquidação na carteira sem expor dados pessoais
  const adminMsgs = repository.listMessages('5511900000000');
  assert.equal(adminMsgs.length, 1);
  assert.match(adminMsgs[0].body, /Cripto Liquidada Direto na Carteira/i);

  // 3. Idempotência: segundo disparo do mesmo webhook é ignorado com segurança
  const dup = await engine.handleSettlementWebhook({
    provider: 'mock',
    externalId: createdOrder.externalId,
    newStatus: 'SETTLED_CRYPTO',
    txHash: 'tx_liquid_confidencial_998877',
    rawEventName: 'MOCK_SETTLED_CRYPTO',
  });
  assert.equal(dup.changed, false);

  repository.close();
});

test('Guardião de Validade (ExpirationWatcher) avisa antes de vencer e expira chaves Pix pontualmente', async () => {
  const { repository, engine, watcher } = createPrivacyTestSetup();
  const phone = '5521977776666';

  await engine.handleIncomingMessage({ phone, text: 'Oi, quero pagar' });
  await engine.handleIncomingMessage({ phone, text: '120,00' });

  const order = repository.listRecentOrders()[0];
  assert.equal(order.status, 'PENDING');

  // Faltando 2 minutos para vencer -> envia lembrete único
  const twoMinBefore = new Date(new Date(order.expiresAt).getTime() - 2 * 60_000);
  const sweep1 = await watcher.sweepPendingOrders(twoMinBefore);
  assert.equal(sweep1.warnedCount, 1);
  assert.equal(sweep1.expiredCount, 0);

  // 1 segundo após vencer -> invalida chave e orienta o pagador no WhatsApp
  const afterExpiry = new Date(new Date(order.expiresAt).getTime() + 1_000);
  const sweep2 = await watcher.sweepPendingOrders(afterExpiry);
  assert.equal(sweep2.expiredCount, 1);
  assert.equal(repository.getOrderById(order.id)?.status, 'EXPIRED');

  repository.close();
});

test('DePixAppProvider (Zero CPF), Hodle e NoxPay validam Webhooks HMAC com segurança', () => {
  assert.equal(parseBrlAmountFromText('pix de 1.500,50'), 1500.5);

  const depixApp = new DePixAppProvider({
    apiUrl: 'https://api.depixapp.com/api',
    apiKey: 'sk_test_123',
    webhookSecret: 'depix_secret',
  });
  assert.equal(depixApp.requiresPayerDocument, false);

  const depixBody = JSON.stringify({
    id: 'chk_123',
    status: 'completed',
    net_amount: 9800,
    metadata: { external_id: 'ord_priv_1' },
  });
  const depixSig = crypto.createHmac('sha256', 'depix_secret').update(depixBody).digest('hex');
  assert.equal(depixApp.verifyWebhookSignature(depixBody, { 'x-depix-signature': depixSig }), true);

  const parsedDepix = depixApp.parseWebhookPayload(JSON.parse(depixBody));
  assert.equal(parsedDepix?.newStatus, 'SETTLED_CRYPTO');
  assert.equal(parsedDepix?.externalId, 'ord_priv_1');
  assert.equal(parsedDepix?.cryptoAmount, 98);

  const hodle = new HodleProvider({
    apiUrl: 'https://api.hodle.com.br',
    apiKey: 'test_key',
    webhookSecret: 'segredo_hodle',
  });
  const hodleBody = JSON.stringify({
    event: 'DEPOSIT_ASSET_SUCCESS',
    data: { id: 'dep_1', externalId: 'ord_1', txHash: '0x999', amount: '50.25' },
  });
  const hodleSig = crypto.createHmac('sha256', 'segredo_hodle').update(hodleBody).digest('hex');
  assert.equal(hodle.verifyWebhookSignature(hodleBody, { 'x-hodle-signature': hodleSig }), true);

  const nox = new NoxPayProvider({
    apiUrl: 'https://api.noxpay.io/v2',
    apiKey: 'nox_key',
    webhookSecret: 'nox_secret',
  });
  const noxBody = JSON.stringify({ txid: 'tx_10', external_id: 'ord_2', status: 'COMPLETED' });
  const noxSig = crypto
    .createHash('sha256')
    .update('nox_secret' + noxBody)
    .digest('base64');
  assert.equal(nox.verifyWebhookSignature(noxBody, { 'x-signature': noxSig }), true);
});
