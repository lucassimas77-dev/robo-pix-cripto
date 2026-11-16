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
import { ConversationEngine } from '../src/services/conversationEngine.ts';
import { ExpirationWatcher } from '../src/services/expirationWatcher.ts';
import { extractDocumentFromText, parseBrlAmountFromText } from '../src/utils/cpfCnpjValidator.ts';
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
    requirePayerDocument: false,
    adminWhatsappPhone: '5511900000000',
  };

  const repository = new OrderRepository(':memory:');
  const provider = new MockProvider({ requiresPayerDocument: false });
  const whatsapp = new UnifiedWhatsAppGateway(config, repository);
  const engine = new ConversationEngine(config, repository, provider, whatsapp);
  const watcher = new ExpirationWatcher(repository, whatsapp, config.pixWarningBeforeMinutes, engine);

  return { config, repository, provider, whatsapp, engine, watcher };
}

test('Fluxo Privado: Cliente envia valor no WhatsApp e recebe cobrança imediata + liquidação idempotente', async () => {
  const { repository, engine } = createPrivacyTestSetup();
  const clientPhone = '5511988887777';

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

  const msgs = repository.listMessages(clientPhone);
  assert.equal(msgs.length, 3);
  assert.equal(msgs[2].type, 'PIX_CODE');
  assert.equal(msgs[2].body, createdOrder.pixCopyPaste);

  // Liquidação -> confirma e nunca retrocede de SETTLED_CRYPTO para PIX_CONFIRMED
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

  // Webhook atrasado de PIX_CONFIRMED jamais rebaixa pedido já liquidado
  const lateProcessing = await engine.handleSettlementWebhook({
    provider: 'mock',
    externalId: createdOrder.externalId,
    newStatus: 'PIX_CONFIRMED',
    rawEventName: 'LATE_PROCESSING',
  });
  assert.equal(lateProcessing.changed, false);
  assert.equal(repository.getOrderById(createdOrder.id)?.status, 'SETTLED_CRYPTO');

  repository.close();
});

test('Guardião de Validade (ExpirationWatcher) avisa antes de vencer, expira pendentes e NÃO expira pedidos já pagos (PIX_CONFIRMED)', async () => {
  const { repository, engine, watcher } = createPrivacyTestSetup();
  const phone1 = '5521977776666';
  const phone2 = '5521966665555';

  await engine.handleIncomingMessage({ phone: phone1, text: 'pix de 120,00' });
  await engine.handleIncomingMessage({ phone: phone2, text: 'pix de 80,00' });

  const allOrders = repository.listRecentOrders();
  const unpaidOrder = allOrders.find((o) => o.customerPhone === phone1)!;
  const paidProcessingOrder = allOrders.find((o) => o.customerPhone === phone2)!;

  // Pedido 2 já teve o Pix pago (em processamento on-chain)
  await engine.handleSettlementWebhook({
    provider: 'mock',
    externalId: paidProcessingOrder.externalId,
    newStatus: 'PIX_CONFIRMED',
    rawEventName: 'PIX_PAID',
  });

  const twoMinBefore = new Date(new Date(unpaidOrder.expiresAt).getTime() - 2 * 60_000);
  const sweep1 = await watcher.sweepPendingOrders(twoMinBefore);
  assert.equal(sweep1.warnedCount, 1);

  const afterExpiry = new Date(new Date(unpaidOrder.expiresAt).getTime() + 5_000);
  const sweep2 = await watcher.sweepPendingOrders(afterExpiry);
  assert.equal(sweep2.expiredCount, 1);
  assert.equal(repository.getOrderById(unpaidOrder.id)?.status, 'EXPIRED');
  // Pedido já pago continua PIX_CONFIRMED (nunca é expirado por engano!)
  assert.equal(repository.getOrderById(paidProcessingOrder.id)?.status, 'PIX_CONFIRMED');

  repository.close();
});

test('DePixAppProvider segue 100% do contrato oficial (POST /products kind=charge sem CPF, POST /checkouts com pix.qr_code, GET embrulhado em checkout e HMAC t=,v1=)', async () => {
  // Extração combinada de valor + CPF na mesma frase
  const combined = 'me manda um pix de 75,50 cpf 529.982.247-25';
  assert.equal(extractDocumentFromText(combined).document, '52998224725');
  assert.equal(parseBrlAmountFromText(combined), 75.5);

  // Sobe um servidor fake imitando exatamente os formatos da API oficial https://api.depixapp.com
  const fakeDepixServer = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};

    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'POST' && req.url === '/api/products') {
      assert.equal(body.kind, 'charge');
      assert.equal(body.amount, 5000);
      assert.ok(typeof body.due_date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(body.due_date));
      res.writeHead(201);
      res.end(
        JSON.stringify({
          product: {
            id: 'prd_test999',
            amount: 5000,
            payment_url: 'https://pay.depixapp.com/c/prd_test999',
          },
        })
      );
      return;
    }

    if (req.method === 'GET' && req.url?.startsWith('/api/products/prd_test999/checkouts')) {
      res.writeHead(200);
      res.end(
        JSON.stringify({
          checkouts: [
            {
              id: 'chk_from_prd',
              status: 'completed',
              is_live: 1,
              blockchain_tx_id: 'liquid_tx_from_charge_123',
            },
          ],
        })
      );
      return;
    }

    if (req.method === 'POST' && req.url === '/api/checkouts') {
      assert.equal(body.amount, 7550);
      assert.equal(body.payer_tax_number, '52998224725');
      assert.equal(body.payment_method, 'pix');
      res.writeHead(201);
      res.end(
        JSON.stringify({
          id: 'chk_direct_1',
          status: 'pending',
          amount: 7550,
          expires_at: new Date(Date.now() + 900_000).toISOString(),
          payment_url: 'https://pay.depixapp.com/chk_direct_1',
          pix: {
            qr_code: '00020126580014br.gov.bcb.pix0136depix-real-emv-payload',
          },
        })
      );
      return;
    }

    if (req.method === 'GET' && req.url === '/api/checkouts/chk_direct_1') {
      // Formato oficial da DePix: embrulhado em `{ checkout: { ... } }`!
      res.writeHead(200);
      res.end(
        JSON.stringify({
          checkout: {
            id: 'chk_direct_1',
            status: 'completed',
            is_live: 1,
            blockchain_tx_id: 'liquid_tx_direct_456',
          },
        })
      );
      return;
    }

    res.writeHead(404);
    res.end('{}');
  });

  await new Promise<void>((resolve) => fakeDepixServer.listen(0, '127.0.0.1', resolve));
  const addr = fakeDepixServer.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  try {
    const depix = new DePixAppProvider({
      apiUrl: baseUrl,
      apiKey: 'sk_live_realkey123456',
      webhookSecret: 'whsec_depix_real',
    });

    // 1. Modo Zero CPF no WhatsApp -> cria Charge privada `prd_test999`
    const zeroCpfCharge = await depix.createCharge({
      externalId: 'ord_zero_cpf',
      amountBrl: 50,
      customerPhone: '5511999999999',
      walletAddress: 'lq1qq...',
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      expirationMinutes: 15,
      webhookUrl: 'https://robo-pix-cripto.onrender.com/webhooks/depixapp',
    });
    assert.equal(zeroCpfCharge.providerChargeId, 'prd_test999');
    assert.equal(zeroCpfCharge.pixCopyPaste, 'https://pay.depixapp.com/c/prd_test999');

    const polledPrd = await depix.checkChargeStatus('prd_test999');
    assert.equal(polledPrd?.status, 'SETTLED_CRYPTO');
    assert.equal(polledPrd?.txHash, 'liquid_tx_from_charge_123');

    // 2. Modo Direto com CPF -> extrai `pix.qr_code` (`000201...`) e lê `{ checkout: ... }`
    const directCharge = await depix.createCharge({
      externalId: 'ord_direct_cpf',
      amountBrl: 75.5,
      customerPhone: '5511999999999',
      payerDocument: '52998224725',
      walletAddress: 'lq1qq...',
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      expirationMinutes: 15,
      webhookUrl: 'https://robo-pix-cripto.onrender.com/webhooks/depixapp',
    });
    assert.equal(directCharge.providerChargeId, 'chk_direct_1');
    assert.ok(directCharge.pixCopyPaste.startsWith('00020126580014br.gov.bcb.pix'));

    const polledChk = await depix.checkChargeStatus('chk_direct_1');
    assert.equal(polledChk?.status, 'SETTLED_CRYPTO');
    assert.equal(polledChk?.txHash, 'liquid_tx_direct_456');

    // 3. Assinatura oficial X-DePix-Signature: t=1717257600,v1=<hmac(t.rawBody)>
    const whBody = JSON.stringify({
      event: 'checkout.completed',
      data: {
        id: 'chk_direct_1',
        status: 'completed',
        is_live: true,
        amount: 7550,
        metadata: { external_id: 'ord_direct_cpf' },
      },
    });
    const ts = '1717257600';
    const v1 = crypto
      .createHmac('sha256', 'whsec_depix_real')
      .update(`${ts}.${whBody}`)
      .digest('hex');
    assert.equal(
      depix.verifyWebhookSignature(whBody, { 'x-depix-signature': `t=${ts},v1=${v1}` }),
      true
    );

    // Bloqueia eventos sandbox (`is_live: false`) quando operando com chave `sk_live_`!
    const fakeSandboxOnLive = depix.parseWebhookPayload({
      event: 'checkout.completed',
      data: { id: 'chk_fake', status: 'completed', is_live: false },
    });
    assert.equal(fakeSandboxOnLive, null);
  } finally {
    fakeDepixServer.close();
  }

  // Valida também Hodle e NoxPay
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
