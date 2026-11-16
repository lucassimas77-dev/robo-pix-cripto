import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { loadConfig } from '../src/config/env.ts';
import type { AppConfig } from '../src/config/env.ts';
import { OrderRepository } from '../src/database/orderRepository.ts';
import { DePixAppProvider } from '../src/providers/depixAppProvider.ts';
import { HodleProvider } from '../src/providers/hodleProvider.ts';
import { MockProvider } from '../src/providers/mockProvider.ts';
import { NoxPayProvider } from '../src/providers/noxPayProvider.ts';
import { createAppHttpServer } from '../src/server/httpServer.ts';
import { ConversationEngine } from '../src/services/conversationEngine.ts';
import { ExpirationWatcher } from '../src/services/expirationWatcher.ts';
import { formatTimeSaoPaulo, parseBrlAmountFromText } from '../src/utils/cpfCnpjValidator.ts';
import { UnifiedWhatsAppGateway } from '../src/whatsapp/whatsappGateway.ts';

function createPrivacyTestSetup() {
  const config: AppConfig = {
    ...loadConfig(),
    cryptoProvider: 'mock',
    whatsappMode: 'simulator',
    adminPassword: '',
    walletAddress: '0xCarteiraTeste',
    walletAsset: 'USDT',
    walletNetwork: 'POLYGON',
    pixExpirationMinutes: 15,
    pixWarningBeforeMinutes: 3,
    adminWhatsappPhone: '5511900000000',
  };

  const repository = new OrderRepository(':memory:');
  const provider = new MockProvider({ webhookSecret: 'test_mock_secret' });
  const whatsapp = new UnifiedWhatsAppGateway(config, repository);
  const engine = new ConversationEngine(config, repository, provider, whatsapp);
  const watcher = new ExpirationWatcher(
    repository,
    whatsapp,
    config.pixWarningBeforeMinutes,
    engine
  );

  return { config, repository, provider, whatsapp, engine, watcher };
}

test('Parsing monetário trata pontuação final, milhar, horários, telefones, datas e "1 pix"', () => {
  assert.equal(parseBrlAmountFromText('pix 1.000'), 1000);
  assert.equal(parseBrlAmountFromText('quero pix de 1.500'), 1500);
  assert.equal(parseBrlAmountFromText('pix de 1.250,50.'), 1250.5);
  assert.equal(parseBrlAmountFromText('Pix de 150.'), 150);
  assert.equal(parseBrlAmountFromText('50,00.'), 50);
  assert.equal(parseBrlAmountFromText('Me manda um pix de 50, por favor'), 50);
  assert.equal(parseBrlAmountFromText('Oi, quero fazer 1 pix'), null);
  assert.equal(parseBrlAmountFromText('Me manda 1 pix'), null);
  assert.equal(parseBrlAmountFromText('quero 2 itens de 50'), null);
  assert.equal(parseBrlAmountFromText('vou pagar dia 16/11 ate 10h R$ 150,00'), 150);
  assert.equal(parseBrlAmountFromText('meu tel é (11) 98888-7777 quero pix de R$ 50'), 50);
  assert.equal(parseBrlAmountFromText('manda pix de 80 reais.'), 80);
  assert.equal(formatTimeSaoPaulo('2026-07-01T18:15:00.000Z'), '15:15');
});

test('Concorrência, mensagens pós-pagamento ("já paguei"), estado AWAITING_AMOUNT pós-erro e alerta de FAILED ao Admin', async () => {
  const { repository, engine } = createPrivacyTestSetup();
  const clientPhone = '5511988887777';
  const clientLid = '998877665544@lid';

  await Promise.all([
    engine.handleIncomingMessage({
      phone: clientPhone,
      customerJid: clientLid,
      text: 'Me manda um Pix de R$ 250,00.',
    }),
    engine.handleIncomingMessage({
      phone: clientPhone,
      customerJid: clientLid,
      text: 'Me manda um Pix de R$ 250,00.',
    }),
  ]);

  assert.equal(repository.listRecentOrders().length, 1);
  const firstOrder = repository.listRecentOrders()[0];

  // Mensagem "Pronto, já paguei o pix de 250" NÃO cria nova cobrança duplicada!
  await engine.handleIncomingMessage({
    phone: clientPhone,
    customerJid: clientLid,
    text: 'Pronto, já paguei o pix de 250!',
  });
  assert.equal(repository.listRecentOrders().length, 1);

  // Transição para FAILED avisa tanto cliente quanto adminWhatsappPhone!
  await engine.handleSettlementWebhook({
    provider: 'mock',
    externalId: firstOrder.externalId,
    newStatus: 'FAILED',
    rawEventName: 'TEST_REFUNDED',
  });
  const adminMsgs = repository.listMessages('5511900000000');
  assert.equal(adminMsgs.length, 1);
  assert.match(adminMsgs[0].body, /Estornado\/Cancelado/i);

  // Valor acima do máximo mantém sessão em AWAITING_AMOUNT para aceitar próximo número puro!
  await engine.handleIncomingMessage({
    phone: clientPhone,
    customerJid: clientLid,
    text: 'pix de 90000',
  });
  assert.equal(repository.getSession(clientPhone).stage, 'AWAITING_AMOUNT');

  repository.close();
});

test('Servidor HTTP bloqueia Bearer password brute-force, CSRF cross-site, NaN em minutos e processa Webhook DePix com X-DePix-Event-Id == data.event_id', async () => {
  const { config, repository, engine } = createPrivacyTestSetup();
  const server = createAppHttpServer({ config, repository, engine });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  const url = `http://127.0.0.1:${port}`;

  try {
    // 1. Setup inicial da senha
    const setupRes = await fetch(`${url}/api/auth/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'minha_senha_segura' }),
    });
    assert.equal(setupRes.status, 200);
    const authCookie = (setupRes.headers.get('set-cookie') || '').split(';')[0];

    // 2. Enviar a senha crua em Authorization: Bearer NÃO autentica (força uso de /api/auth/login com rate-limit!)
    const rawPwdBearer = await fetch(`${url}/api/account`, {
      headers: { Authorization: 'Bearer minha_senha_segura' },
    });
    assert.equal(rawPwdBearer.status, 401);

    // 3. CSRF cross-site bloqueado com 403!
    const csrfAttempt = await fetch(`${url}/api/account`, {
      method: 'POST',
      headers: {
        Cookie: authCookie,
        'Content-Type': 'application/json',
        'Sec-Fetch-Site': 'cross-site',
      },
      body: JSON.stringify({ provider: 'mock' }),
    });
    assert.equal(csrfAttempt.status, 403);

    // 4. pixExpirationMinutes inválido ("abc" -> NaN) é sanitizado para inteiro seguro sem quebrar!
    const nanUpdate = await fetch(`${url}/api/account`, {
      method: 'POST',
      headers: { Cookie: authCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: 'depixapp',
        apiKey: 'sk_live_key1234567890',
        webhookSecret: 'whsec_e2e_depix',
        pixExpirationMinutes: 'abc',
      }),
    });
    assert.equal(nanUpdate.status, 200);

    // 5. Teste E2E CRÍTICO: Webhook real da DePix onde X-DePix-Event-Id === data.event_id atualiza o pedido na 1ª entrega e deduplica na 2ª!
    repository.createOrder({
      id: crypto.randomUUID(),
      externalId: 'ord_e2e_webhook_1',
      provider: 'depixapp',
      providerChargeId: 'prd_e2e_1',
      customerPhone: '5511977776666',
      amountBrl: 100,
      estimatedCryptoAmount: 97.01,
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      walletAddress: 'Carteira Liquid',
      pixCopyPaste: 'https://pay.depixapp.com/c/prd_e2e_1',
      status: 'PENDING',
      warningSent: false,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 900_000).toISOString(),
    });

    const whPayload = JSON.stringify({
      event: 'checkout.completed',
      data: {
        event_id: 'evt_same_id_header_and_body',
        id: 'chk_999',
        product_id: 'prd_e2e_1',
        status: 'completed',
        is_live: true,
        amount: 10000,
        metadata: { external_id: 'ord_e2e_webhook_1' },
      },
    });
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = crypto
      .createHmac('sha256', 'whsec_e2e_depix')
      .update(`${ts}.${whPayload}`)
      .digest('hex');

    const whRes1 = await fetch(`${url}/webhooks/depixapp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-DePix-Signature': `t=${ts},v1=${sig}`,
        'X-DePix-Event-Id': 'evt_same_id_header_and_body',
      },
      body: whPayload,
    });
    assert.equal(whRes1.status, 200);
    const whJson1 = (await whRes1.json()) as Record<string, unknown>;
    assert.equal(whJson1.changed, true);

    const updated = repository.findOrderByWebhookIds({
      provider: 'depixapp',
      externalId: 'ord_e2e_webhook_1',
    });
    assert.equal(updated?.status, 'SETTLED_CRYPTO');

    // Reentrega idêntica do mesmo webhook é deduplicada com 200 duplicate: true!
    const whRes2 = await fetch(`${url}/webhooks/depixapp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-DePix-Signature': `t=${ts},v1=${sig}`,
        'X-DePix-Event-Id': 'evt_same_id_header_and_body',
      },
      body: whPayload,
    });
    assert.equal(whRes2.status, 200);
    const whJson2 = (await whRes2.json()) as Record<string, unknown>;
    assert.equal(whJson2.duplicate, true);
  } finally {
    server.close();
    repository.close();
  }
});

test('DePixAppProvider detecta estorno (cancelled -> FAILED) em prd_..., prioriza completed e protege rate-limit', async () => {
  let mode: 'cancelled_only' | 'completed_too' = 'cancelled_only';

  const fakeDepixServer = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'GET' && req.url?.startsWith('/api/products/prd_refund_test/checkouts')) {
      if (mode === 'cancelled_only') {
        res.writeHead(200);
        res.end(
          JSON.stringify({
            checkouts: [
              {
                id: 'chk_1',
                status: 'cancelled',
                is_live: 1,
                rejection_reasons: ['PAYER_MISMATCH'],
              },
            ],
          })
        );
        return;
      }
      res.writeHead(200);
      res.end(
        JSON.stringify({
          checkouts: [
            { id: 'chk_1', status: 'cancelled', is_live: 1 },
            { id: 'chk_2', status: 'completed', is_live: 1 },
          ],
        })
      );
      return;
    }

    if (req.method === 'GET' && req.url === '/api/checkouts/chk_2') {
      res.writeHead(200);
      res.end(
        JSON.stringify({
          checkout: {
            id: 'chk_2',
            status: 'completed',
            is_live: 1,
            blockchain_tx_id: 'tx_liquid_ok',
          },
        })
      );
      return;
    }
    res.writeHead(404);
    res.end('{}');
  });

  await new Promise<void>((resolve) => fakeDepixServer.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${(fakeDepixServer.address() as { port: number }).port}`;

  try {
    const depix = new DePixAppProvider({
      apiUrl: baseUrl,
      apiKey: 'sk_live_key123',
      webhookSecret: 'sec',
    });

    const pollRefunded = await depix.checkChargeStatus('prd_refund_test');
    assert.equal(pollRefunded?.status, 'FAILED');
    assert.deepEqual(pollRefunded?.rejectionReasons, ['PAYER_MISMATCH']);

    mode = 'completed_too';
    const pollPaid = await depix.checkChargeStatus('prd_refund_test');
    assert.equal(pollPaid?.status, 'SETTLED_CRYPTO');
    assert.equal(pollPaid?.txHash, 'tx_liquid_ok');
  } finally {
    fakeDepixServer.close();
  }

  const hodle = new HodleProvider({ apiUrl: 'https://api.hodle.com.br', apiKey: 'k', webhookSecret: '' });
  assert.equal(hodle.verifyWebhookSignature('{}', { 'x-hodle-signature': 'a' }), false);

  const nox = new NoxPayProvider({ apiUrl: 'https://api.noxpay.io/v2', apiKey: 'k', webhookSecret: '' });
  assert.equal(nox.verifyWebhookSignature('{}', { 'x-signature': 'a' }), false);
});
