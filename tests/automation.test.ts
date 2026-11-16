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

test('Parsing monetário em Português trata milhar com ponto, horários, telefones e ambiguidades sem erro', () => {
  assert.equal(parseBrlAmountFromText('pix 1.000'), 1000);
  assert.equal(parseBrlAmountFromText('quero pix de 1.500'), 1500);
  assert.equal(parseBrlAmountFromText('pix de 1.250,50'), 1250.5);
  assert.equal(parseBrlAmountFromText('75,50'), 75.5);
  assert.equal(parseBrlAmountFromText('75.50'), 75.5);
  // Ambiguidade ("2 itens de 50") retorna null para perguntar o valor total!
  assert.equal(parseBrlAmountFromText('quero 2 itens de 50'), null);
  // Horário + R$ explícito captura 150,00 e ignora 10h
  assert.equal(parseBrlAmountFromText('vou pagar ate 10h R$ 150,00'), 150);
  // Telefone + R$ explícito captura 50 e ignora DDD/telefone
  assert.equal(parseBrlAmountFromText('meu tel é (11) 98888-7777 quero pix de R$ 50'), 50);
  assert.equal(parseBrlAmountFromText('meu telefone é 11988887777 quero pix de R$ 50'), 50);
  assert.equal(parseBrlAmountFromText('manda pix de 80 reais'), 80);

  // Horário de Brasília fixo (UTC 18:15 = 15:15 em America/Sao_Paulo)
  assert.equal(formatTimeSaoPaulo('2026-07-01T18:15:00.000Z'), '15:15');
});

test('Concorrência por telefone, máquina de estados AWAITING_ACTIVE_ORDER_DECISION e persistência de JID @lid', async () => {
  const { repository, engine } = createPrivacyTestSetup();
  const clientPhone = '5511988887777';
  const clientLid = '998877665544@lid';

  // Duas mensagens simultâneas do mesmo telefone NÃO criam 2 cobranças paralelas!
  await Promise.all([
    engine.handleIncomingMessage({
      phone: clientPhone,
      customerJid: clientLid,
      text: 'Me manda um Pix de R$ 250,00',
    }),
    engine.handleIncomingMessage({
      phone: clientPhone,
      customerJid: clientLid,
      text: 'Me manda um Pix de R$ 250,00',
    }),
  ]);

  const orders = repository.listRecentOrders();
  assert.equal(orders.length, 1);
  assert.equal(orders[0].customerJid, clientLid);

  // Cliente está em AWAITING_ACTIVE_ORDER_DECISION e manda "300" sem escolher 1 ou 2 -> NÃO cria 2º Pix!
  await engine.handleIncomingMessage({
    phone: clientPhone,
    customerJid: clientLid,
    text: '300',
  });
  assert.equal(repository.listRecentOrders().length, 1);

  // Agora escolhe "2" -> cancela a de 250 e cria a de 300!
  await engine.handleIncomingMessage({
    phone: clientPhone,
    customerJid: clientLid,
    text: '2',
  });
  const afterSwitch = repository.listRecentOrders();
  assert.equal(afterSwitch.length, 2);
  assert.equal(afterSwitch[0].amountBrl, 300);
  assert.equal(afterSwitch[0].status, 'PENDING');
  assert.equal(afterSwitch[1].status, 'CANCELLED');

  repository.close();
});

test('Servidor HTTP exige autenticação em /api/*, bloqueia JSON inválido com 400 e protege segredos', async () => {
  const { config, repository, engine } = createPrivacyTestSetup();
  const server = createAppHttpServer({ config, repository, engine });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  const url = `http://127.0.0.1:${port}`;

  try {
    // 1. Sem login: /api/account e /api/orders retornam 401!
    const unauthAcc = await fetch(`${url}/api/account`);
    assert.equal(unauthAcc.status, 401);
    const unauthOrd = await fetch(`${url}/api/orders`);
    assert.equal(unauthOrd.status, 401);

    // 2. Primeiro acesso cria senha via /api/auth/setup e recebe cookie HttpOnly
    const setupRes = await fetch(`${url}/api/auth/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'minha_senha_segura' }),
    });
    assert.equal(setupRes.status, 200);
    const cookie = setupRes.headers.get('set-cookie') || '';
    assert.match(cookie, /HttpOnly/i);

    // 3. Segunda tentativa de /api/auth/setup é bloqueada com 403!
    const hijackAttempt = await fetch(`${url}/api/auth/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'outra' }),
    });
    assert.equal(hijackAttempt.status, 403);

    // 4. Com cookie válido: /api/account funciona e JSON malformado retorna 400 (nunca 500!)
    const authCookie = cookie.split(';')[0];
    const okAcc = await fetch(`${url}/api/account`, {
      headers: { Cookie: authCookie },
    });
    assert.equal(okAcc.status, 200);
    const accJson = (await okAcc.json()) as Record<string, unknown>;
    assert.equal(accJson.apiKey, undefined);

    const badJson = await fetch(`${url}/api/account`, {
      method: 'POST',
      headers: { Cookie: authCookie, 'Content-Type': 'application/json' },
      body: '{malformed',
    });
    assert.equal(badJson.status, 400);

    const badProvider = await fetch(`${url}/api/account`, {
      method: 'POST',
      headers: { Cookie: authCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'inexistente' }),
    });
    assert.equal(badProvider.status, 400);
  } finally {
    server.close();
    repository.close();
  }
});

test('DePixAppProvider envia slug único em kind=charge, prioriza completed sobre cancelled, busca blockchain_tx_id e valida janela t= no HMAC', async () => {
  const fakeDepixServer = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};

    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'POST' && req.url === '/api/products') {
      assert.equal(body.kind, 'charge');
      assert.equal(body.amount, 5000);
      assert.match(String(body.slug), /^chg-[a-z0-9]+-[a-f0-9]{10}$/);
      res.writeHead(201);
      res.end(
        JSON.stringify({
          product: {
            id: 'prd_audit_1',
            amount: 5000,
            payment_url: 'https://pay.depixapp.com/c/prd_audit_1',
          },
        })
      );
      return;
    }

    if (req.method === 'GET' && req.url?.startsWith('/api/products/prd_audit_1/checkouts')) {
      // Simula 1ª tentativa `cancelled` seguida de 2ª tentativa `completed` (sem blockchain_tx_id na listagem!)
      res.writeHead(200);
      res.end(
        JSON.stringify({
          checkouts: [
            { id: 'chk_failed_first', status: 'cancelled', is_live: 1 },
            { id: 'chk_paid_second', status: 'completed', is_live: 1 },
          ],
        })
      );
      return;
    }

    if (req.method === 'GET' && req.url === '/api/checkouts/chk_paid_second') {
      res.writeHead(200);
      res.end(
        JSON.stringify({
          checkout: {
            id: 'chk_paid_second',
            status: 'completed',
            is_live: 1,
            blockchain_tx_id: 'liquid_tx_fetched_from_detail_999',
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
      apiKey: 'sk_live_realkey123456',
      webhookSecret: 'whsec_depix_real',
    });

    const charge = await depix.createCharge({
      externalId: 'ord_audit_1',
      amountBrl: 50,
      customerPhone: '5511999999999',
      walletAddress: '',
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      expirationMinutes: 15,
      webhookUrl: 'https://robo-pix-cripto.onrender.com/webhooks/depixapp',
    });
    assert.equal(charge.providerChargeId, 'prd_audit_1');
    assert.equal(charge.pixCopyPaste, 'https://pay.depixapp.com/c/prd_audit_1');

    // Prioriza `completed` sobre `cancelled` e busca `blockchain_tx_id` no detalhe!
    const polled = await depix.checkChargeStatus('prd_audit_1');
    assert.equal(polled?.status, 'SETTLED_CRYPTO');
    assert.equal(polled?.txHash, 'liquid_tx_fetched_from_detail_999');

    // HMAC válido dentro da janela de 5 min
    const whBody = JSON.stringify({
      event: 'checkout.completed',
      data: {
        event_id: 'evt_123',
        id: 'chk_paid_second',
        product_id: 'prd_audit_1',
        status: 'completed',
        is_live: true,
        amount: 5000,
      },
    });
    const nowSec = String(Math.floor(Date.now() / 1000));
    const v1Valid = crypto
      .createHmac('sha256', 'whsec_depix_real')
      .update(`${nowSec}.${whBody}`)
      .digest('hex');
    assert.equal(
      depix.verifyWebhookSignature(whBody, { 'x-depix-signature': `t=${nowSec},v1=${v1Valid}` }),
      true
    );

    // Replay attack antigo (timestamp de 2020) é rejeitado!
    const oldTs = '1580000000';
    const v1Old = crypto
      .createHmac('sha256', 'whsec_depix_real')
      .update(`${oldTs}.${whBody}`)
      .digest('hex');
    assert.equal(
      depix.verifyWebhookSignature(whBody, { 'x-depix-signature': `t=${oldTs},v1=${v1Old}` }),
      false
    );
  } finally {
    fakeDepixServer.close();
  }

  // Verifica que provedores sem webhookSecret rejeitam qualquer webhook!
  const hodleNoSecret = new HodleProvider({
    apiUrl: 'https://api.hodle.com.br',
    apiKey: 'k',
    webhookSecret: '',
  });
  assert.equal(hodleNoSecret.verifyWebhookSignature('{}', { 'x-hodle-signature': 'abc' }), false);

  const noxNoSecret = new NoxPayProvider({
    apiUrl: 'https://api.noxpay.io/v2',
    apiKey: 'k',
    webhookSecret: '',
  });
  assert.equal(noxNoSecret.verifyWebhookSignature('{}', { 'x-signature': 'abc' }), false);
});
