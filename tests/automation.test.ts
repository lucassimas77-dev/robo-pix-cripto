import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { clampInt, loadConfig } from '../src/config/env.ts';
import type { AppConfig } from '../src/config/env.ts';
import { OrderRepository } from '../src/database/orderRepository.ts';
import { DePixAppProvider } from '../src/providers/depixAppProvider.ts';
import { HodleProvider } from '../src/providers/hodleProvider.ts';
import { MockProvider } from '../src/providers/mockProvider.ts';
import { NoxPayProvider } from '../src/providers/noxPayProvider.ts';
import { createAppHttpServer } from '../src/server/httpServer.ts';
import { ConversationEngine } from '../src/services/conversationEngine.ts';
import { ExpirationWatcher } from '../src/services/expirationWatcher.ts';
import {
  formatTimeSaoPaulo,
  hasPixTriggerKeyword,
  isCancelCommand,
  isExitCommand,
  isPaymentConfirmationMessage,
  isPublicHttpsWebhookUrl,
  isStatusQueryMessage,
  normalizeCommandText,
  normalizeUtcIsoTimestamp,
  parseActiveOrderMenuReply,
  parseBrlAmountFromText,
  stripTrailingSlashes,
} from '../src/utils/cpfCnpjValidator.ts';
import { BaileysDirectManager } from '../src/whatsapp/baileysManager.ts';
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
  assert.equal(parseBrlAmountFromText('R$ 50 pix'), 50);
  assert.equal(parseBrlAmountFromText('Pix - 50'), 50);

  // Proteções contra negativos, porcentagens, IDs de pedido, quantidades de pix e parcelas
  assert.equal(parseBrlAmountFromText('-50'), null);
  assert.equal(parseBrlAmountFromText('pix de -50'), null);
  assert.equal(parseBrlAmountFromText('-50 reais'), null);
  assert.equal(parseBrlAmountFromText('R$ -50'), null);
  assert.equal(parseBrlAmountFromText('Tem 10% de desconto no pix?'), null);
  assert.equal(parseBrlAmountFromText('Quero pagar o pedido 150 no pix'), null);
  assert.equal(parseBrlAmountFromText('Pix pedido #80'), null);
  assert.equal(parseBrlAmountFromText('quero fazer 5 pix'), null);
  assert.equal(parseBrlAmountFromText('me manda 2 pix'), null);
  assert.equal(parseBrlAmountFromText('divide em 3x no pix?'), null);
  assert.equal(parseBrlAmountFromText('o pix vence em 15 minutos?'), null);
  assert.equal(parseBrlAmountFromText('quero 2 itens de R$ 50'), null);
  assert.equal(parseBrlAmountFromText('O pix é de R$ 50 ou R$ 100?'), null);
  assert.equal(parseBrlAmountFromText('50 reais ou 80 reais?'), null);
  assert.equal(parseBrlAmountFromText('Pix de R$ 50 ou 100?'), null);
  assert.equal(parseBrlAmountFromText('pix de R$ 50 agora ou 100 amanhã?'), null);
  assert.equal(parseBrlAmountFromText('pix de R$ 50 + 30'), null);
  assert.equal(parseBrlAmountFromText('meu zap é 11 98888-7777 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('meu cel 21 98888-7777 manda pix'), null);
  assert.equal(parseBrlAmountFromText('meu email é lucas2025@hotmail.com manda um pix'), null);
  assert.equal(parseBrlAmountFromText('nao consegui abrir https://pay.depixapp.com/c/prd_99abc'), null);
  assert.equal(parseBrlAmountFromText('manda pix pro @cliente10'), null);
  assert.equal(parseBrlAmountFromText('cep 01310-100 quero fazer pix'), null);
  assert.equal(parseBrlAmountFromText('conta 56789-0 quero pix'), null);
  assert.equal(parseBrlAmountFromText('pix de 50 (11) 98888-7777'), 50);

  // Casos da Busca #12: CPF/CNPJ/CEP pontuado/RG/datas ISO, telefones sem hífen, +55 colado, mil/centavos
  assert.equal(parseBrlAmountFromText('meu cpf é 005.200.789-00 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('meu cep é 05.310-100 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('meu rg é 12.345.678-9 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('meu cpf é 123.456.789-00 manda pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('vou pagar dia 2026-11-17 R$ 50,00'), 50);
  assert.equal(parseBrlAmountFromText('agencia 1234 conta 56789-0 quero pix'), null);
  assert.equal(parseBrlAmountFromText('meu zap é (11) 988887777 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('meu zap é 11 988887777 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('meu zap é +55(11)98888-7777 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('pix de 50 centavos'), 0.5);
  assert.equal(parseBrlAmountFromText('tem taxa de 99 centavos no pix?'), null);
  assert.equal(parseBrlAmountFromText('pix de 5 mil'), 5000);
  assert.equal(parseBrlAmountFromText('pix de 1,5 mil'), 1500);
  assert.equal(parseBrlAmountFromText('pix de 50 reais e 25 centavos'), 50.25);

  // Confirmações de pagamento com valor antes de "pago" vs "eu pago 50" / "pago 50?"
  assert.equal(isPaymentConfirmationMessage('R$ 50,00 pago!'), true);
  assert.equal(isPaymentConfirmationMessage('50 reais pago no pix'), true);
  assert.equal(isPaymentConfirmationMessage('Pago o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Feito o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Eu pago 50 no pix'), false);
  assert.equal(isPaymentConfirmationMessage('Pago 50 no pix?'), false);

  // Normalização UTC em microssegundos e rejeição de anos > 9999 + URL pública HTTPS sem IPs privados
  assert.equal(normalizeUtcIsoTimestamp(1763337600000000), '2025-11-17T00:00:00.000Z');
  assert.equal(normalizeUtcIsoTimestamp('+057847-12-12T00:00:00.000Z', '2026-01-01T00:00:00.000Z'), '2026-01-01T00:00:00.000Z');
  assert.equal(isPublicHttpsWebhookUrl('https://robo-pix-cripto.onrender.com/webhooks/depixapp'), true);
  assert.equal(isPublicHttpsWebhookUrl('https://127.0.0.1:3000/webhooks/depixapp'), false);
  assert.equal(isPublicHttpsWebhookUrl('https://192.168.1.10/webhooks/depixapp'), false);
  assert.equal(isPublicHttpsWebhookUrl('https://10.0.0.5/webhooks/depixapp'), false);
  assert.equal(isPublicHttpsWebhookUrl('https://172.16.0.1/webhooks/depixapp'), false);
  assert.equal(isPublicHttpsWebhookUrl('https://[::1]:3000/webhooks/depixapp'), false);
  assert.equal(isPublicHttpsWebhookUrl('https://localhost./webhooks/depixapp'), false);
  assert.equal(isPublicHttpsWebhookUrl('https://./webhooks/depixapp'), false);
  assert.equal(isPublicHttpsWebhookUrl('https://app.internal./webhooks/depixapp'), false);
  assert.equal(isPublicHttpsWebhookUrl('https://[::127.0.0.1]/webhooks/depixapp'), false);
  assert.equal(isPublicHttpsWebhookUrl('https://[febf::1]/webhooks/depixapp'), false);

  // Casos da Busca #13: vírgulas inválidas (150,555 / 1,500), compostos "mil e ...", centavos >= 100, rótulos com ':', DDD 011, 2 pix de 50, .pdf, /mes, CNPJ alfanumérico
  assert.equal(parseBrlAmountFromText('R$ 150,555'), null);
  assert.equal(parseBrlAmountFromText('pix de 150,555'), null);
  assert.equal(parseBrlAmountFromText('pix de 1,500'), null);
  assert.equal(parseBrlAmountFromText('pix de 1,255 mil'), null);
  assert.equal(parseBrlAmountFromText('pix de 10,50 centavos'), null);
  assert.equal(parseBrlAmountFromText('pix de 1.500 reais e 50 centavos'), 1500.5);
  assert.equal(parseBrlAmountFromText('pix de 150 centavos'), 1.5);
  assert.equal(parseBrlAmountFromText('pix de 500 centavos'), 5);
  assert.equal(parseBrlAmountFromText('pix de 2 mil e 500 reais'), 2500);
  assert.equal(parseBrlAmountFromText('pix de R$ 2 mil e 500'), 2500);
  assert.equal(parseBrlAmountFromText('pix de R$ 50 e 30 reais'), null);
  assert.equal(parseBrlAmountFromText('pix de mil reais'), 1000);
  assert.equal(parseBrlAmountFromText('pix de um mil reais'), 1000);
  assert.equal(parseBrlAmountFromText('ag: 1234 conta: 56789-0 quero pix'), null);
  assert.equal(parseBrlAmountFromText('pedido: 150 quero pix'), null);
  assert.equal(parseBrlAmountFromText('id: 500 quero pix'), null);
  assert.equal(parseBrlAmountFromText('meu tel (011) 98888-7777 quero pix'), null);
  assert.equal(parseBrlAmountFromText('meu tel 011 98888-7777 quero pix'), null);
  assert.equal(parseBrlAmountFromText('quero 2 pix de 50'), null);
  assert.equal(parseBrlAmountFromText('quero fazer 1 pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('segue arquivo 15.pdf quero pix'), null);
  assert.equal(parseBrlAmountFromText('acesse meu site 50.io quero pix'), null);
  assert.equal(parseBrlAmountFromText('custa 100/mes no pix?'), null);
  assert.equal(parseBrlAmountFromText('meu cnpj é 12.ABC.345/01DE-35 quero pix'), null);

  // Casos da Busca #13 em isPaymentConfirmationMessage e parseActiveOrderMenuReply
  assert.equal(isPaymentConfirmationMessage('Pago R$ 50'), false);
  assert.equal(isPaymentConfirmationMessage('Pago R$ 50,00 no pix'), false);
  assert.equal(isPaymentConfirmationMessage('Pago R$ 50 agora'), false);
  assert.equal(isPaymentConfirmationMessage('Pago R$ 50 se fizer desconto'), false);
  assert.equal(isPaymentConfirmationMessage('Por R$ 50 pago agora'), false);
  assert.deepEqual(parseActiveOrderMenuReply('2.'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('manda de novo'), {
    choice: 'resend',
    explicitOptionDigit: null,
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('quero a 2'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('quero a opção 2'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('cancela e gera de 100'), {
    choice: 'new',
    explicitOptionDigit: null,
    inlineNewAmountBrl: 100,
  });

  // Casos da Busca #14: composições completas com "mil/reais/centavos", "mais", conflito R$/reais, .50, +55 colado ao DDD, HH:MM:SS, YYYY/MM/DD e Markdown WhatsApp
  assert.equal(parseBrlAmountFromText('pix de 5 mil reais'), 5000);
  assert.equal(parseBrlAmountFromText('R$ 5 mil reais'), 5000);
  assert.equal(parseBrlAmountFromText('pix de 1,5 mil reais'), 1500);
  assert.equal(parseBrlAmountFromText('pix de 2 mil reais e 50 centavos'), 2000.5);
  assert.equal(parseBrlAmountFromText('2 mil e 50 centavos'), 2000.5);
  assert.equal(parseBrlAmountFromText('mil e 50 centavos'), 1000.5);
  assert.equal(parseBrlAmountFromText('mil e 500 reais'), 1500);
  assert.equal(parseBrlAmountFromText('manda mil e 500 no pix'), 1500);
  assert.equal(parseBrlAmountFromText('quero um pix de mil e 500'), 1500);
  assert.equal(parseBrlAmountFromText('manda mil no pix'), 1000);
  assert.equal(parseBrlAmountFromText('pix de R$ 50 mais 30'), null);
  assert.equal(parseBrlAmountFromText('pix de 50 mais 30 reais'), null);
  assert.equal(parseBrlAmountFromText('era 100 reais agora é R$ 80?'), null);
  assert.equal(parseBrlAmountFromText('pix de .50'), null);
  assert.equal(parseBrlAmountFromText('meu zap é +55 11988887777 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('meu zap é +55 1198888-7777 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('meu zap é 55 11988887777 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('quero pagar até 14:30:15 no pix'), null);
  assert.equal(parseBrlAmountFromText('vou pagar em 2026/11/17 no pix'), null);
  assert.equal(parseBrlAmountFromText('pix de _50,00_'), 50);
  assert.equal(parseBrlAmountFromText('pix de *150,00*'), 150);
  assert.equal(isStatusQueryMessage('O pix de 50 deu certo?'), true);
  assert.equal(isStatusQueryMessage('Chegou o pix de 50?'), true);
  assert.equal(isStatusQueryMessage('Bateu o pix de 50 aí?'), true);
  assert.equal(isStatusQueryMessage('Foi confirmado o pix de 50?'), true);
  assert.equal(isStatusQueryMessage('O pagamento de 50 foi aprovado?'), true);
  assert.equal(isExitCommand('*sair*'), true);
  assert.equal(isCancelCommand('*cancelar*'), true);
  assert.equal(isStatusQueryMessage('*status*'), true);
  assert.equal(isPaymentConfirmationMessage('*pago*'), true);

  // Proteção anti-ReDoS O(N) em mensagens gigantes (64 KB) + clampInt seguro
  const startRedos = performance.now();
  const adv1 = 'a' + '!'.repeat(60_000) + 'a';
  const adv2 = 'a' + ' '.repeat(60_000) + 'b';
  const adv3 = 'a' + ' '.repeat(50_000) + '1 pix '.repeat(1_000);
  const adv4 = '10' + ' '.repeat(1_950) + 'x';
  const adv5 = '1' + '.000'.repeat(495) + 'a';
  const adv6 = '1.'.repeat(950) + 'a';
  const advSlashes = '/'.repeat(65_536) + 'a';
  assert.equal(stripTrailingSlashes(advSlashes).length, 65_537);
  assert.equal(stripTrailingSlashes('https://api.depixapp.com///'), 'https://api.depixapp.com');
  for (const s of [adv1, adv2, adv3, adv4, adv5, adv6]) {
    assert.equal(parseBrlAmountFromText(s), null);
    assert.equal(normalizeCommandText(s), '');
    assert.equal(isCancelCommand(s), false);
    assert.equal(isPaymentConfirmationMessage(s), false);
  }
  assert.ok(performance.now() - startRedos < 50, 'NLU deve executar em tempo O(1)/O(N) < 50ms');

  assert.equal(clampInt('', 3000, 1, 65535), 3000);
  assert.equal(clampInt('   ', 15, 5, 20), 15);
  assert.equal(clampInt(null, 15, 5, 20), 15);
  assert.equal(clampInt(false, 15, 5, 20), 15);
  assert.equal(clampInt({ toString: null }, 15, 5, 20), 15);

  // Parser do menu 1 / 2 sem colisão com "atual" e sem corromper "2)", "*2*", "opção 2", "2 - ..."
  assert.deepEqual(parseActiveOrderMenuReply('Cancelar a atual e gerar 80'), {
    choice: 'new',
    explicitOptionDigit: null,
    inlineNewAmountBrl: 80,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2 - Cancelar a atual e gerar R$ 80,00'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 80,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Trocar a atual'), {
    choice: 'new',
    explicitOptionDigit: null,
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Não quero reenviar, quero novo'), {
    choice: 'new',
    explicitOptionDigit: null,
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2)'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('*2*'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('opção 2'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2 - quero outro'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2 - gerar 120'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 120,
  });
  assert.deepEqual(parseActiveOrderMenuReply('1)'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });

  // Casos da Busca #15: menu 1 / 2 com "2 mil reais" / "1 mil" / "2 reais", numerais por extenso, multiplicação/subtração/intervalos, filtro "apagar" e confirmações com advérbios
  assert.deepEqual(parseActiveOrderMenuReply('2 mil reais'), {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: 2000,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Quero 2 mil'), {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: 2000,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2 mil e 500 reais'), {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: 2500,
  });
  assert.deepEqual(parseActiveOrderMenuReply('1 mil reais'), {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: 1000,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Quero 2 reais'), {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: 2,
  });

  assert.equal(parseBrlAmountFromText('pix de dois mil reais'), 2000);
  assert.equal(parseBrlAmountFromText('quero um pix de cinco mil'), 5000);
  assert.equal(parseBrlAmountFromText('pix de tres mil e 500'), 3500);
  assert.equal(parseBrlAmountFromText('pix de três mil e quinhentos reais'), 3500);
  assert.equal(parseBrlAmountFromText('pix de mil e quinhentos'), 1500);
  assert.equal(parseBrlAmountFromText('pix de dez mil reais'), 10000);
  assert.equal(parseBrlAmountFromText('pix de vinte e cinco mil'), 25000);
  assert.equal(parseBrlAmountFromText('pix de cento e cinquenta reais'), 150);
  assert.equal(parseBrlAmountFromText('100 reais e cinquenta centavos'), 100.5);
  assert.equal(parseBrlAmountFromText('pix de dois mil e meio'), 2500);
  assert.equal(parseBrlAmountFromText('depois das cinco faço o pix'), null);
  assert.equal(parseBrlAmountFromText('quantos mil pode no pix?'), null);
  assert.equal(parseBrlAmountFromText('pix de doiz mil'), null);

  assert.equal(parseBrlAmountFromText('pix de 2*50'), null);
  assert.equal(parseBrlAmountFromText('3*50 reais'), null);
  assert.equal(parseBrlAmountFromText('pix de 2 * 50 reais'), null);
  assert.equal(parseBrlAmountFromText('*2* * *50*'), null);
  assert.equal(parseBrlAmountFromText('pix de R$ 50 - 10'), null);
  assert.equal(parseBrlAmountFromText('pix de 100 - 20 reais'), null);
  assert.equal(parseBrlAmountFromText('pix de 100 menos 20 reais'), null);
  assert.equal(parseBrlAmountFromText('pix de 50 a 100 reais?'), null);
  assert.equal(parseBrlAmountFromText('*Pix* de *50,00*'), 50);

  assert.equal(hasPixTriggerKeyword('Vou apagar as 10 fotos'), false);
  assert.equal(hasPixTriggerKeyword('Pode apagar aquela mensagem'), false);
  assert.equal(hasPixTriggerKeyword('Não precisa propagar isso'), false);
  assert.equal(hasPixTriggerKeyword('Quero pagar 50'), true);
  assert.equal(hasPixTriggerKeyword('Manda o pix de 50'), true);

  assert.equal(isPaymentConfirmationMessage('Fiz agora o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Enviei agora R$ 50'), true);
  assert.equal(isPaymentConfirmationMessage('Mandei aí os 50 no pix'), true);
  assert.equal(isPaymentConfirmationMessage('Transferi agora 50 reais'), true);
  assert.equal(isPaymentConfirmationMessage('Já mandei lá o pix de 80'), true);
  assert.equal(isPaymentConfirmationMessage('Já transferi pra vc os 50'), true);
  assert.equal(isPaymentConfirmationMessage('Pronto, 50 enviado!'), true);
  assert.equal(isPaymentConfirmationMessage('Valor de R$ 50 transferido'), true);

  // Casos da Busca #16: gramática padrão "dois mil duzentos e cinquenta", múltiplos números conflitantes,
  // horários ("às 10", "depois das 6", "3 da tarde"), "dia 15", "taxa no pix de 100", plurais/femininos pós-pagamento e menu com ",", "!" e "quero"
  assert.equal(
    parseBrlAmountFromText('Me manda um pix de dois mil duzentos e cinquenta reais'),
    2250
  );
  assert.equal(parseBrlAmountFromText('pix de mil duzentos e cinquenta reais'), 1250);
  assert.equal(parseBrlAmountFromText('pix de dois mil, quinhentos reais'), 2500);
  assert.equal(parseBrlAmountFromText('pix de dois mil duzentos e cinquenta'), 2250);
  assert.equal(parseBrlAmountFromText('pix de 2 mil 250 reais'), 2250);

  assert.equal(parseBrlAmountFromText('Vou levar 3 de R$ 50 no pix'), null);
  assert.equal(parseBrlAmountFromText('Pix de R$ 50, ops 80'), null);
  assert.equal(parseBrlAmountFromText('Era R$ 50 mas agora é 80'), null);
  assert.equal(parseBrlAmountFromText('pix de R$ 100 / 2'), null);
  assert.equal(parseBrlAmountFromText('pix de 100 reais dividido por 2'), null);

  assert.equal(parseBrlAmountFromText('depois das 6 faço o pix'), null);
  assert.equal(parseBrlAmountFromText('te mando o pix às 10'), null);
  assert.equal(parseBrlAmountFromText('9 da manhã mando o pix'), null);
  assert.equal(parseBrlAmountFromText('preciso da 2ª via do pix'), null);
  assert.equal(parseBrlAmountFromText('vou fazer o pix 3 da tarde'), null);
  assert.equal(parseBrlAmountFromText('8 da noite mando o pix'), null);
  assert.equal(parseBrlAmountFromText('vou pagar no pix dia 15'), null);
  assert.equal(parseBrlAmountFromText('bom dia 20'), 20);
  assert.equal(parseBrlAmountFromText('Tem taxa no pix de 100?'), null);

  assert.equal(isPaymentConfirmationMessage('50 reais pagos!'), true);
  assert.equal(isPaymentConfirmationMessage('Os 50 reais já foram pagos no pix'), true);
  assert.equal(isPaymentConfirmationMessage('A cobrança de 50 já foi paga'), true);
  assert.equal(isPaymentConfirmationMessage('Transferência pix realizada de R$ 50,00'), true);
  assert.equal(isPaymentConfirmationMessage('Transação pix efetuada R$ 50,00'), true);
  assert.equal(isPaymentConfirmationMessage('Pago! R$ 50,00'), true);
  assert.equal(isPaymentConfirmationMessage('Feito, pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Segue o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Pix de cinquenta reais pago'), true);

  assert.deepEqual(parseActiveOrderMenuReply('2, quero R$ 100'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 100,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2 quero 100'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 100,
  });
  assert.deepEqual(parseActiveOrderMenuReply('1! manda aí'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });

  // Casos da Busca #17: centavos coloquiais por extenso, "dois mil e um", autocorreção por extenso,
  // "10:30h"/"14:30min"/"1 mês"/"5 semanas"/"nº 50", NBSP pós-pagamento, negação "não paguei" e novo pedido >= 10
  assert.equal(parseBrlAmountFromText('pix de dez e cinquenta'), 10.5);
  assert.equal(parseBrlAmountFromText('pix de vinte e cinco e cinquenta'), 25.5);
  assert.equal(parseBrlAmountFromText('pix de dois mil e um'), 2001);
  assert.equal(parseBrlAmountFromText('pix de mil e um'), 1001);
  assert.equal(parseBrlAmountFromText('pix de cinquenta, ops oitenta'), null);
  assert.equal(parseBrlAmountFromText('pix de cinquenta não, oitenta'), null);
  assert.equal(parseBrlAmountFromText('pix de 20 reais e 50'), 20.5);
  assert.equal(parseBrlAmountFromText('pix de vinte reais e cinquenta'), 20.5);

  assert.equal(parseBrlAmountFromText('10:30h mando o pix'), null);
  assert.equal(parseBrlAmountFromText('14:30min mando o pix'), null);
  assert.equal(parseBrlAmountFromText('pago em 1 mês no pix'), null);
  assert.equal(parseBrlAmountFromText('assinatura de 1 mes no pix'), null);
  assert.equal(parseBrlAmountFromText('daqui a 5 semanas mando o pix'), null);
  assert.equal(parseBrlAmountFromText('moro no nº 50 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('Quero pagar cinquenta no pix'), 50);
  assert.equal(parseBrlAmountFromText('Me manda cinquenta no pix'), 50);
  assert.equal(parseBrlAmountFromText('Me manda cinquenta por favor'), 50);
  assert.equal(parseBrlAmountFromText('Faz cinquenta aí no pix'), 50);
  assert.equal(parseBrlAmountFromText('Oi, mil por favor'), 1000);

  assert.equal(isPaymentConfirmationMessage('Enviei R$\u00A050,00'), true);
  assert.equal(isPaymentConfirmationMessage('Enviei agora mesmo o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Fiz pelo Nubank o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Mandei pelo banco o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Transferi pra sua conta o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Fiz aqui rapidinho o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Já paguei aquele, agora quero um pix de 50'), false);
  assert.equal(isStatusQueryMessage('Confirmou! Gera um pix de 80'), false);
  assert.equal(isStatusQueryMessage('Deu tudo certo! Agora me manda um pix de 100'), false);
  assert.equal(isPaymentConfirmationMessage('Não paguei o pix de 50 ainda'), false);
  assert.equal(isPaymentConfirmationMessage('Paguei não, quero um pix de 50'), false);

  // Casos da Busca #18: horários compostos por extenso ("às duas e trinta", "seis e trinta da tarde", "10h 30"),
  // "15 de novembro", quantidades de itens ("10 ingressos", "5 unidades"), intervalos com "um", telefones com ponto/"9 ",
  // Unicode NFD, "Fiz uma compra de 50", "envia mil reais" e negação no menu ("Não quero cancelar", "Não cancela, manda a atual")
  assert.equal(parseBrlAmountFromText('Te mando o pix às duas e trinta'), null);
  assert.equal(parseBrlAmountFromText('Te mando o pix às quatro e vinte'), null);
  assert.equal(parseBrlAmountFromText('Depois das cinco e trinta faço o pix'), null);
  assert.equal(parseBrlAmountFromText('Te mando o pix às vinte e duas'), null);
  assert.equal(parseBrlAmountFromText('Vou fazer o pix seis e trinta da tarde'), null);
  assert.equal(parseBrlAmountFromText('Vou fazer o pix seis e meia da tarde'), null);
  assert.equal(parseBrlAmountFromText('Te mando o pix às 10h 30'), null);
  assert.equal(parseBrlAmountFromText('Pago em 15 de novembro no pix'), null);
  assert.equal(parseBrlAmountFromText('Vou pagar R$ 100 em 15 de novembro no pix'), 100);

  assert.equal(parseBrlAmountFromText('Oi, quero comprar 10 ingressos no pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 5 unidades, aceita pix?'), null);
  assert.equal(parseBrlAmountFromText('Preciso de 20 peças, posso pagar no pix?'), null);
  assert.equal(parseBrlAmountFromText('Quero 15 cotas no pix'), null);

  assert.equal(parseBrlAmountFromText('pix entre um e dois mil'), null);
  assert.equal(parseBrlAmountFromText('pix de um a dois mil'), null);
  assert.equal(parseBrlAmountFromText('pix de um ou dois mil'), null);
  assert.equal(parseBrlAmountFromText('pix de um ou dois reais'), null);

  assert.equal(parseBrlAmountFromText('Meu zap é (21) 98888.7777, quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('Meu zap é (21) 9.8888.7777, quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('Meu zap é (11) 9 8888-7777, manda um pix de 50'), 50);

  assert.equal(isPaymentConfirmationMessage('Fiz uma compra de 50, pode mandar o pix?'), false);
  assert.equal(isPaymentConfirmationMessage('Fiz o pedido agora me passa o pix de 50'), false);
  assert.equal(isPaymentConfirmationMessage('Gera R$ 50 aí que já envio o comprovante'), false);
  assert.equal(
    isPaymentConfirmationMessage('Já paguei aquele, agora manda um pix de mil reais'),
    false
  );
  assert.equal(isStatusQueryMessage('Confirmou! Agora gera um pix de mil reais'), false);
  assert.equal(parseBrlAmountFromText('envia mil reais no pix'), 1000);
  assert.equal(parseBrlAmountFromText('passa mil reais no pix'), 1000);
  assert.equal(isPaymentConfirmationMessage('Na\u0303o paguei o pix de 50 ainda'), false);
  assert.equal(parseBrlAmountFromText('pix de tre\u0302s mil'), 3000);

  assert.deepEqual(parseActiveOrderMenuReply('Não quero cancelar'), {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Não cancela, manda a atual'), {
    choice: 'resend',
    explicitOptionDigit: null,
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Não precisa trocar, mantém essa'), {
    choice: 'resend',
    explicitOptionDigit: null,
    inlineNewAmountBrl: null,
  });

  // Casos da Busca #19: "Acabei de fazer/mandar/passar o pix de 50", "Consegui pagar", "Me manda o comprovante",
  // "Cancela o pix de 50", negações/desistências, cripto/moedas estrangeiras, medidas/endereços e "50reais" colado
  assert.equal(isPaymentConfirmationMessage('Acabei de fazer o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Acabei de mandar R$ 50'), true);
  assert.equal(isPaymentConfirmationMessage('Acabei de passar o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Consegui pagar o pix de 50!'), true);
  assert.equal(isPaymentConfirmationMessage('Consegui fazer o pix de 50!'), true);
  assert.equal(isStatusQueryMessage('Pode mandar o comprovante do pix de 50?'), true);
  assert.equal(isStatusQueryMessage('Pode enviar o comprovante de R$ 50?'), true);
  assert.equal(isStatusQueryMessage('Me manda o comprovante do pix de 50'), true);

  assert.equal(isCancelCommand('Cancela o pix de 50'), true);
  assert.equal(isCancelCommand('Quero cancelar a cobrança de R$ 50,00'), true);
  assert.equal(isCancelCommand('Pode cancelar a cobrança de 50?'), true);
  assert.equal(isCancelCommand('cancela e gera de 100'), false);
  assert.equal(parseBrlAmountFromText('Cancela o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não quero pagar 50 no pix'), null);
  assert.equal(parseBrlAmountFromText('Não vou pagar R$ 50 agora'), null);
  assert.equal(parseBrlAmountFromText('Não gera o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não manda o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não quero mais o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Esquece o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Deixa pra lá o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Desisto do pix de 50'), null);

  assert.equal(parseBrlAmountFromText('Quero comprar 100 USDT, manda o pix'), null);
  assert.equal(parseBrlAmountFromText('Quanto fica US$ 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('50 dólares no pix'), null);
  assert.equal(parseBrlAmountFromText('0,05 BTC no pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 2 kg no pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 5 litros no pix'), null);
  assert.equal(parseBrlAmountFromText('Moro na rua 10, quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('Moro no km 50, aceita pix?'), null);
  assert.equal(parseBrlAmountFromText('pix de 50reais'), 50);
  assert.equal(parseBrlAmountFromText('100reais no pix'), 100);
  assert.equal(parseBrlAmountFromText('50,00reais'), 50);

  // Casos da Busca #20: "R$ 1.500 pix" / "50,75 pix", medidas/horas decimais ("10,5 kg", "10,5h", "50 m2", "50,12345678"),
  // cripto/moedas por extenso ou com "mil", pós-pagamento com entrega/print/descontou, desistências com infinitivo,
  // somas de mesmo valor ("50 reais + 50 reais", "3333 3333"), menu "dois" / "1 - reenviar sem cancelar" e "pras"/"ap"
  assert.equal(parseBrlAmountFromText('R$ 1.500 pix'), 1500);
  assert.equal(parseBrlAmountFromText('1.500 pix'), 1500);
  assert.equal(parseBrlAmountFromText('R$ 50,75 pix'), 50.75);
  assert.equal(parseBrlAmountFromText('50,75 pix'), 50.75);
  assert.equal(parseBrlAmountFromText('Quero 10,5 kg no pix'), null);
  assert.equal(parseBrlAmountFromText('Preciso de 2,5 metros, posso pagar no pix?'), null);
  assert.equal(parseBrlAmountFromText('Quero 1.500 kg no pix'), null);
  assert.equal(parseBrlAmountFromText('Daqui a 10,5 horas mando o pix'), null);
  assert.equal(parseBrlAmountFromText('Daqui a 10,5h mando o pix'), null);
  assert.equal(parseBrlAmountFromText('Preciso de 50 m2 no pix'), null);
  assert.equal(parseBrlAmountFromText('pix de 50,12345678'), null);

  assert.equal(parseBrlAmountFromText('Quanto fica cinquenta dólares no pix?'), null);
  assert.equal(parseBrlAmountFromText('Quanto fica US$ cinquenta no pix?'), null);
  assert.equal(parseBrlAmountFromText('Quero comprar cem USDT, manda o pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 2 mil USDT, manda o pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 5 mil satoshis no pix'), null);

  assert.equal(isPaymentConfirmationMessage('Já paguei o pix de 50, pode mandar o produto?'), true);
  assert.equal(isPaymentConfirmationMessage('Paguei os R$ 50, me envia o acesso!'), true);
  assert.equal(isPaymentConfirmationMessage('Posso mandar print do comprovante de R$ 50?'), true);
  assert.equal(
    isPaymentConfirmationMessage('Vou enviar foto do comprovante do pix de 50'),
    true
  );
  assert.equal(
    isPaymentConfirmationMessage('Pronto, vou mandar o comprovante do pix de 50'),
    true
  );
  assert.equal(
    isStatusQueryMessage('Tentei pagar o pix de 50 e descontou da minha conta'),
    true
  );
  assert.equal(isStatusQueryMessage('O pix de 50 descontou mas deu erro'), true);
  assert.equal(isStatusQueryMessage('Descontou 50 reais da minha conta no pix'), true);

  assert.equal(parseBrlAmountFromText('Desisti de fazer o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Esquece de fazer o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não consigo pagar R$ 50 no pix'), null);
  assert.equal(parseBrlAmountFromText('Não precisa mais do pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não quero de 50 no pix'), null);
  assert.equal(isCancelCommand('Cancela o pix de cinquenta reais'), true);

  assert.equal(parseBrlAmountFromText('pix de 50 reais + 50 reais'), null);
  assert.equal(parseBrlAmountFromText('quero um pix de 50 reais e outro de 50 reais'), null);
  assert.equal(parseBrlAmountFromText('Meu tel é 3333 3333 quero fazer pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 2 kg de R$ 50 no pix'), null);
  assert.equal(parseBrlAmountFromText('Preciso de 3 metros de R$ 20 no pix'), null);

  assert.deepEqual(parseActiveOrderMenuReply('dois'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('quero a dois'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('1 - reenviar sem cancelar'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });

  assert.equal(parseBrlAmountFromText('Te mando o pix lá pras 18'), null);
  assert.equal(parseBrlAmountFromText('pras seis faço o pix'), null);
  assert.equal(parseBrlAmountFromText('Moro no ap 20, quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('Moro no apt 12, quero fazer um pix'), null);

  // Cobertura Busca #21: moedas/cripto simétricas, logradouros, negações compostas/erros/estornos, "pago" com hora/data, cancele, Nª opção e "50R$"
  assert.equal(parseBrlAmountFromText('50 US$ no pix'), null);
  assert.equal(parseBrlAmountFromText('50 U$ no pix'), null);
  assert.equal(parseBrlAmountFromText('50 CAD no pix'), null);
  assert.equal(parseBrlAmountFromText('100 ARS no pix'), null);
  assert.equal(parseBrlAmountFromText('Quanto custa dólar 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Quero 50 MATIC no pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 0,5 LBTC no pix'), null);
  assert.equal(parseBrlAmountFromText('meio milhão de satoshis no pix'), null);

  assert.equal(parseBrlAmountFromText('Entrega na Rua Tiradentes, 85, manda o pix'), null);
  assert.equal(parseBrlAmountFromText('Moro na Av. Paulista, 1000, aceita pix?'), null);
  assert.equal(parseBrlAmountFromText('Estou na Rodovia BR-101, aceita pix?'), null);
  assert.equal(parseBrlAmountFromText('Moro na Rua Tiradentes, 85, manda um pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Moro na Rua Tiradentes, manda um pix de 50'), 50);

  assert.equal(parseBrlAmountFromText('Não vou conseguir fazer o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não vou poder pagar os 50 no pix'), null);
  assert.equal(parseBrlAmountFromText('Deixa quieto o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Mandei errado R$ 50 no pix'), null);
  assert.equal(parseBrlAmountFromText('Deu erro no pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não passou o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Meu banco recusou o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Quero estorno do pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Me devolve os 50 do pix'), null);
  assert.equal(isStatusQueryMessage('Mandei errado R$ 50 no pix'), true);
  assert.equal(isStatusQueryMessage('Deu erro no pix de 50'), true);
  assert.equal(isStatusQueryMessage('Meu banco recusou o pix de 50'), true);
  assert.equal(isStatusQueryMessage('Deu erro no pix anterior, manda outro de 50'), false);
  assert.equal(parseBrlAmountFromText('Deu erro no pix anterior, manda outro de 50'), 50);

  assert.equal(isPaymentConfirmationMessage('Hoje às 18 pago 50 no pix'), false);
  assert.equal(parseBrlAmountFromText('Hoje às 18 pago 50 no pix'), 50);
  assert.equal(isPaymentConfirmationMessage('Até as 14 pago R$ 80 no pix'), false);
  assert.equal(parseBrlAmountFromText('Até as 14 pago R$ 80 no pix'), 80);
  assert.equal(isPaymentConfirmationMessage('Dia 15 pago R$ 100 no pix'), false);
  assert.equal(parseBrlAmountFromText('Dia 15 pago R$ 100 no pix'), 100);
  assert.equal(isPaymentConfirmationMessage('Às 18h pago o pix de 50'), false);
  assert.equal(parseBrlAmountFromText('Às 18h pago o pix de 50'), 50);

  assert.equal(isCancelCommand('Cancele o pix'), true);
  assert.equal(isCancelCommand('Cancela esse pix aí'), true);
  assert.deepEqual(parseActiveOrderMenuReply('primeira opção'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('quero a segunda opção'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('segunda opção, gerar 80'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 80,
  });
  assert.equal(parseBrlAmountFromText('pix de 50R$'), 50);
  assert.equal(parseBrlAmountFromText('50,75R$ no pix'), 50.75);

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

  // Transição para FAILED avisa tanto cliente quanto adminWhatsappPhone e ativa AWAITING_AMOUNT!
  await engine.handleSettlementWebhook({
    provider: 'mock',
    externalId: firstOrder.externalId,
    newStatus: 'FAILED',
    rawEventName: 'TEST_REFUNDED',
  });
  assert.equal(repository.getSession(clientPhone).stage, 'AWAITING_AMOUNT');
  const adminMsgs = repository.listMessages('5511900000000');
  assert.equal(adminMsgs.length, 1);
  assert.match(adminMsgs[0].body, /Estornado\/Cancelado/i);

  // Webhook atrasado fora de ordem de PIX_CONFIRMED NUNCA ressuscita pedido já FAILED!
  const lateProcessingAfterFailed = await engine.handleSettlementWebhook({
    provider: 'mock',
    externalId: firstOrder.externalId,
    newStatus: 'PIX_CONFIRMED',
    rawEventName: 'LATE_PROCESSING_RETRY',
  });
  assert.equal(lateProcessingAfterFailed.changed, false);
  assert.equal(repository.getOrderById(firstOrder.id)?.status, 'FAILED');

  // E updateOrderStatus('EXPIRED') NUNCA sobrescreve pedido que não esteja PENDING!
  assert.equal(
    repository.updateOrderStatus(firstOrder.id, 'EXPIRED', new Date(Date.now() + 9999999).toISOString()),
    false
  );
  assert.equal(repository.getOrderById(firstOrder.id)?.status, 'FAILED');

  // Mesmo após FAILED (ou sem cobrança ativa), "Já paguei o pix de 250" NUNCA cria nova cobrança duplicada!
  await engine.handleIncomingMessage({
    phone: clientPhone,
    customerJid: clientLid,
    text: 'Já paguei o pix de 250',
  });
  assert.equal(repository.listRecentOrders().length, 1);

  // Número novo nunca visto mandando "Fiz o pix de 80" ou "Paguei 50 no pix" não gera cobrança fantasma!
  await engine.handleIncomingMessage({
    phone: '5511955554444',
    text: 'Fiz o pix de 80',
  });
  await engine.handleIncomingMessage({
    phone: '5511955554444',
    text: 'Paguei 50 no pix',
  });
  await engine.handleIncomingMessage({
    phone: '5511955554444',
    text: 'Já fiz o pagamento de 50',
  });
  await engine.handleIncomingMessage({
    phone: '5511955554444',
    text: 'Pagamento de 50 feito',
  });
  for (const receiptMsg of [
    'Comprovante R$ 50,00',
    'Comprovante do pix de 50',
    'Segue meu comprovante de R$ 50',
    'Aqui está o comprovante de 50',
    'Pix de 50 pago!',
    'O pix de R$ 50 já foi pago',
    'Recebeu o pix de 50?',
    'Já recebeu o pix de 50?',
    'Caiu o pix de 50?',
    'Confirmou o pix de 50?',
    'Deu certo o pix de 50?',
    'Fiz 50 no pix',
    'Passei 50 no pix',
    'Depositei 50 no pix',
  ]) {
    await engine.handleIncomingMessage({
      phone: clientPhone,
      customerJid: clientLid,
      text: receiptMsg,
    });
  }
  assert.equal(repository.listRecentOrders().length, 1);

  // Comandos naturais ("Quero cancelar o pix", "Ajuda", "Novo valor de 150" sobrescrevendo valor pendente antigo)
  const phoneMenu = '5511944443333';
  await engine.handleIncomingMessage({ phone: phoneMenu, text: 'Pix de 60' });
  assert.equal(repository.listRecentOrders().length, 2);

  // Envia outro valor ("80") -> entra em AWAITING_ACTIVE_ORDER_DECISION com pendingNewAmountBrl = 80
  await engine.handleIncomingMessage({ phone: phoneMenu, text: '80' });
  assert.equal(repository.getSession(phoneMenu).stage, 'AWAITING_ACTIVE_ORDER_DECISION');
  assert.equal(repository.getSession(phoneMenu).pendingNewAmountBrl, 80);

  // Responde "2)" ou "2 - Cancelar a atual e gerar R$ 150,00" -> cancela R$ 60 e gera R$ 150 (não R$ 80 nem reenvia R$ 60!)
  await engine.handleIncomingMessage({
    phone: phoneMenu,
    text: '2 - Cancelar a atual e gerar R$ 150,00',
  });
  const latestMenuOrder = repository.findMostRecentOrderByPhone(phoneMenu);
  assert.equal(latestMenuOrder?.amountBrl, 150);
  assert.equal(latestMenuOrder?.status, 'PENDING');

  // Testa também "2)" usando pendingNewAmountBrl preservado (R$ 95) sem virar R$ 2,00!
  await engine.handleIncomingMessage({ phone: phoneMenu, text: '95' });
  await engine.handleIncomingMessage({ phone: phoneMenu, text: '2)' });
  assert.equal(repository.findMostRecentOrderByPhone(phoneMenu)?.amountBrl, 95);

  // "Quero cancelar o pix!" cancela a cobrança ativa sem cair em loop
  await engine.handleIncomingMessage({ phone: phoneMenu, text: 'Quero cancelar o pix!' });
  assert.equal(repository.findMostRecentOrderByPhone(phoneMenu)?.status, 'CANCELLED');
  assert.equal(repository.getSession(phoneMenu).stage, 'AWAITING_AMOUNT');

  // "Quero a (2)" preserva pendingNewAmountBrl sem perder o valor pendente!
  await engine.handleIncomingMessage({ phone: phoneMenu, text: 'Pix de 60' });
  // Em IDLE com cobrança ativa, "Reenvia o pix de 60" reenvia direto sem abrir menu contraditório
  await engine.handleIncomingMessage({ phone: phoneMenu, text: 'Reenvia o pix de 60' });
  assert.equal(repository.getSession(phoneMenu).stage, 'IDLE');

  await engine.handleIncomingMessage({ phone: phoneMenu, text: 'Pix de 85' });
  assert.equal(repository.getSession(phoneMenu).stage, 'AWAITING_ACTIVE_ORDER_DECISION');
  // Mesmo 8 minutos após abrir o menu (> 5 min), enquanto a cobrança ativa de 15 min existir, "2" gera R$ 85 e nunca R$ 2!
  const agedMenuSess = repository.getSession(phoneMenu);
  repository.saveSession(
    { ...agedMenuSess, updatedAt: new Date(Date.now() - 8 * 60_000).toISOString() },
    true
  );
  await engine.handleIncomingMessage({ phone: phoneMenu, text: 'Quero a (2)' });
  assert.equal(repository.findMostRecentOrderByPhone(phoneMenu)?.amountBrl, 85);
  await engine.handleIncomingMessage({ phone: phoneMenu, text: 'Cancela o pix de 85' });
  assert.equal(repository.findMostRecentOrderByPhone(phoneMenu)?.status, 'CANCELLED');

  // Comando de ajuda funciona e mantém AWAITING_AMOUNT
  await engine.handleIncomingMessage({ phone: phoneMenu, text: 'Como funciona?' });
  assert.equal(repository.getSession(phoneMenu).stage, 'AWAITING_AMOUNT');

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
  config.publicBaseUrl = 'https://meu-tunel.trycloudflare.com';
  const baileys = new BaileysDirectManager(repository);
  const server = createAppHttpServer({ config, repository, engine, baileys });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  const url = `http://127.0.0.1:${port}`;

  try {
    // 1. Setup inicial da senha (corrida concorrente permite apenas 1 vencedor com 200 e rejeita a outra com 403!)
    const [setupA, setupB] = await Promise.all([
      fetch(`${url}/api/auth/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'minha_senha_segura' }),
      }),
      fetch(`${url}/api/auth/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'senha_invasor_concorrente' }),
      }),
    ]);
    const statuses = [setupA.status, setupB.status].sort();
    assert.deepEqual(statuses, [200, 403]);
    const winnerRes = setupA.status === 200 ? setupA : setupB;
    const winnerPassword =
      setupA.status === 200 ? 'minha_senha_segura' : 'senha_invasor_concorrente';
    const fullSetCookie = winnerRes.headers.get('set-cookie') || '';
    // Em HTTP local puro (mesmo com PUBLIC_BASE_URL https://), não força Secure para não travar navegador local!
    assert.equal(fullSetCookie.includes('Secure'), false);
    const authCookie = fullSetCookie.split(';')[0];

    // E quando chega via proxy HTTPS ("X-Forwarded-Proto: https, http"), emite obrigatoriamente "; Secure"!
    const httpsLoginRes = await fetch(`${url}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'https, http',
      },
      body: JSON.stringify({ password: winnerPassword }),
    });
    assert.equal(httpsLoginRes.status, 200);
    assert.equal((httpsLoginRes.headers.get('set-cookie') || '').includes('Secure'), true);

    // 2. Enviar a senha crua em Authorization: Bearer NÃO autentica (força uso de /api/auth/login com rate-limit!)
    const rawPwdBearer = await fetch(`${url}/api/account`, {
      headers: { Authorization: `Bearer ${winnerPassword}` },
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

    // 4. pixExpirationMinutes inválido ("abc" -> NaN) é sanitizado e chave curta não vaza em apiKeyPreview!
    const nanUpdate = await fetch(`${url}/api/account`, {
      method: 'POST',
      headers: { Cookie: authCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: 'depixapp',
        apiKey: 'shortkey123',
        webhookSecret: 'whsec_e2e_depix',
        pixExpirationMinutes: 'abc',
      }),
    });
    assert.equal(nanUpdate.status, 200);
    const accCheck = await fetch(`${url}/api/account`, { headers: { Cookie: authCookie } });
    const accJson = (await accCheck.json()) as Record<string, unknown>;
    assert.equal(accJson.apiKeyPreview, '•••••••• (Chave salva)');
    assert.equal(String(accJson.apiKeyPreview).includes('shortkey'), false);

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

    // Divergência entre X-DePix-Event-Id e data.event_id assinado é bloqueada com HTTP 400!
    const mismatchPayload = JSON.stringify({
      event: 'checkout.completed',
      data: {
        event_id: 'evt_signed_body_id',
        id: 'chk_999',
        product_id: 'prd_e2e_1',
        status: 'completed',
        is_live: true,
      },
    });
    const sigMismatch = crypto
      .createHmac('sha256', 'whsec_e2e_depix')
      .update(`${ts}.${mismatchPayload}`)
      .digest('hex');
    const whMismatchRes = await fetch(`${url}/webhooks/depixapp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-DePix-Signature': `t=${ts},v1=${sigMismatch}`,
        'X-DePix-Event-Id': 'evt_spoofed_header_id',
      },
      body: mismatchPayload,
    });
    assert.equal(whMismatchRes.status, 400);

    // 6. Filtro allowedTestPhone incompleto (<10 dígitos) é rejeitado com HTTP 400 (fail-closed)!
    const badPhoneFilter = await fetch(`${url}/api/whatsapp/settings`, {
      method: 'POST',
      headers: { Cookie: authCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ filterMode: 'keyword_only', allowedTestPhone: '5511999' }),
    });
    assert.equal(badPhoneFilter.status, 400);

    const goodPhoneFilter = await fetch(`${url}/api/whatsapp/settings`, {
      method: 'POST',
      headers: { Cookie: authCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ filterMode: 'keyword_only', allowedTestPhone: '5511999998888' }),
    });
    assert.equal(goodPhoneFilter.status, 200);

    // 7. Tipos JSON adversariais ({}, {"toString": null}), URI malformada e Host inválido retornam 400/200 limpo (zero HTTP 500)!
    const objApiKeyRes = await fetch(`${url}/api/account`, {
      method: 'POST',
      headers: { Cookie: authCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'depixapp', apiKey: {} }),
    });
    assert.equal(objApiKeyRes.status, 400);

    const nullProtoProvRes = await fetch(`${url}/api/account`, {
      method: 'POST',
      headers: { Cookie: authCookie, 'Content-Type': 'application/json' },
      body: '{"provider":{"toString":null}}',
    });
    assert.equal(nullProtoProvRes.status, 400);

    const badLoginTypeRes = await fetch(`${url}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"password":{"toString":null}}',
    });
    assert.equal(badLoginTypeRes.status, 400);

    // 20 tentativas paralelas de brute-force em /api/auth/login são serializadas e bloqueiam com HTTP 429 a partir da 6ª!
    const parallelBrute = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        fetch(`${url}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: `chute_errado_${i}` }),
        })
      )
    );
    const count429 = parallelBrute.filter((r) => r.status === 429).length;
    assert.ok(count429 >= 15, `Esperado >=15 respostas 429, obtido ${count429}`);
    const afterBruteSeq = await fetch(`${url}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'outro_chute_sequencial' }),
    });
    assert.equal(afterBruteSeq.status, 429);

    const badUriSimRes = await fetch(`${url}/api/simulator/pay/%E0%A4%A`, {
      method: 'POST',
      headers: { Cookie: authCookie },
    });
    assert.equal(badUriSimRes.status, 400);

    // 8. Payload acima de 256 KB recebe HTTP 413 limpo (sem ECONNRESET)!
    const hugeBody = JSON.stringify({ junk: 'x'.repeat(300 * 1024) });
    const tooLargeRes = await fetch(`${url}/api/account`, {
      method: 'POST',
      headers: { Cookie: authCookie, 'Content-Type': 'application/json' },
      body: hugeBody,
    });
    assert.equal(tooLargeRes.status, 413);
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
            null,
            { id: 'chk_1', status: 'cancelled', is_live: 1 },
            { id: 'chk_2', status: 'completed', is_live: 1 },
          ],
        })
      );
      return;
    }

    if (req.method === 'POST' && req.url === '/api/products') {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        const parsed = JSON.parse(raw || '{}') as Record<string, unknown>;
        res.writeHead(201);
        res.end(
          JSON.stringify({
            product: {
              id: parsed.callback_url ? 'prd_with_cb' : 'prd_no_cb',
              payment_url: 'https://pay.depixapp.com/c/prd_test',
            },
          })
        );
      });
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

    // Sub-checkout expirado (`product_id` presente) é ignorado em parseWebhookPayload para não matar `prd_...` prematuramente
    const subExpired = depix.parseWebhookPayload({
      event: 'checkout.expired',
      data: { id: 'chk_sub_1', product_id: 'prd_refund_test', status: 'expired', is_live: true },
    });
    assert.equal(subExpired, null);

    // Campos numéricos malformados ({"toString": null}, "", 0, []) em parseWebhookPayload não lançam TypeError nem gravam 0!
    const advAmt1 = depix.parseWebhookPayload(
      JSON.parse(
        '{"event":"checkout.completed","data":{"id":"chk_adv_1","status":"completed","is_live":true,"amount_received":{"toString":null}}}'
      )
    );
    assert.equal(advAmt1?.newStatus, 'SETTLED_CRYPTO');
    assert.equal(advAmt1?.cryptoAmount, undefined);

    const advAmt2 = depix.parseWebhookPayload({
      event: 'checkout.completed',
      data: { id: 'chk_adv_2', status: 'completed', is_live: true, amount_received: '' },
    });
    assert.equal(advAmt2?.cryptoAmount, undefined);

    // Whitelist estrita fail-closed para is_live em produção ("false", undefined, null, "0" -> rejeita!)
    for (const fakeLive of ['false', '0', undefined, null, false, 0]) {
      assert.equal(
        depix.parseWebhookPayload({
          event: 'checkout.completed',
          data: { id: 'chk_fake_live', status: 'completed', is_live: fakeLive },
        }),
        null
      );
    }

    // Booleanos false / 0 em IDs não viram strings "false"/"0"
    const boolIds = depix.parseWebhookPayload({
      event: 'checkout.completed',
      data: {
        event_id: false,
        id: 'chk_real_999',
        product_id: false,
        status: 'completed',
        is_live: 1,
        blockchain_tx_id: false,
      },
    });
    assert.equal(boolIds?.providerChargeId, 'chk_real_999');
    assert.equal(boolIds?.eventId, undefined);
    assert.equal(boolIds?.txHash, undefined);

    // callback_url só é enviado quando webhookSecret está configurado (evita retentativas 401 na DePix App)
    const depixNoSecret = new DePixAppProvider({
      apiUrl: baseUrl,
      apiKey: 'sk_live_no_sec_key123',
      webhookSecret: '',
    });
    const outNoCb = await depixNoSecret.createCharge({
      externalId: 'ext_no_cb',
      customerPhone: '5511999990000',
      amountBrl: 50,
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      walletAddress: 'Liquid',
      expirationMinutes: 15,
      webhookUrl: 'https://robo-pix-cripto.onrender.com/webhooks/depixapp',
    });
    assert.equal(outNoCb.providerChargeId, 'prd_no_cb');

    const outWithCb = await depix.createCharge({
      externalId: 'ext_with_cb',
      customerPhone: '5511999990000',
      amountBrl: 50,
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      walletAddress: 'Liquid',
      expirationMinutes: 15,
      webhookUrl: 'https://robo-pix-cripto.onrender.com/webhooks/depixapp',
    });
    assert.equal(outWithCb.providerChargeId, 'prd_with_cb');
  } finally {
    fakeDepixServer.close();
  }

  const hodle = new HodleProvider({ apiUrl: 'https://api.hodle.com.br', apiKey: 'k', webhookSecret: '' });
  assert.equal(hodle.verifyWebhookSignature('{}', { 'x-hodle-signature': 'a' }), false);

  const nox = new NoxPayProvider({ apiUrl: 'https://api.noxpay.io/v2', apiKey: 'k', webhookSecret: '' });
  assert.equal(nox.verifyWebhookSignature('{}', { 'x-signature': 'a' }), false);

  // Fallback de texto em UnifiedWhatsAppGateway quando o upload de imagem do QR falha no Baileys
  const { config: gwCfg, repository: gwRepo } = createPrivacyTestSetup();
  try {
    const sentTexts: string[] = [];
    const fakeBaileys = {
      isConnected: () => true,
      sendImageWithCaption: async () => false,
      sendText: async (_p: string, txt: string) => {
        sentTexts.push(txt);
        return true;
      },
    } as unknown as BaileysDirectManager;
    const gw = new UnifiedWhatsAppGateway(gwCfg, gwRepo, fakeBaileys);
    await gw.sendPixCharge({
      phone: '5511999990000',
      summaryText: 'Resumo R$ 50,00',
      pixCopyPaste: 'https://pay.depixapp.com/c/prd_fallback',
      qrCodeBase64: 'data:image/png;base64,AAAA',
    });
    assert.deepEqual(sentTexts, ['Resumo R$ 50,00', 'https://pay.depixapp.com/c/prd_fallback']);
  } finally {
    gwRepo.close();
  }
});

test('ExpirationWatcher protege contra 503 transitório, respeita grace window de 15 min no rail depix e garante 100% de /deactivate em lote', async () => {
  DePixAppProvider.clearRateLimitWindows();
  let return503 = true;
  const deactivatedIds: string[] = [];
  const basePastIso = new Date(Date.now() - 60_000).toISOString();

  const fakeServer = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'POST' && req.url?.endsWith('/deactivate')) {
      const m = req.url.match(/\/api\/products\/([^/]+)\/deactivate/);
      if (m) deactivatedIds.push(decodeURIComponent(m[1]));
      res.writeHead(200);
      res.end(JSON.stringify({ success: true }));
      return;
    }

    if (req.method === 'GET' && req.url?.includes('/checkouts')) {
      if (return503) {
        res.writeHead(503);
        res.end(JSON.stringify({ error: 'temporary_unavailable' }));
        return;
      }
      if (req.url.includes('prd_grace_rail')) {
        // Expirou há 1 min no relógio normal, mas está no rail "depix" (grace window de +15 min!)
        res.writeHead(200);
        res.end(
          JSON.stringify({
            checkouts: [
              {
                id: 'chk_grace_1',
                status: 'pending',
                is_live: 1,
                payment_method: 'depix',
                expires_at: basePastIso,
              },
            ],
          })
        );
        return;
      }
      if (req.url.includes('prd_live_priority')) {
        res.writeHead(200);
        res.end(
          JSON.stringify({
            checkouts: [
              {
                id: 'chk_live_prio',
                status: 'processing',
                is_live: 1,
                payment_method: 'pix',
              },
            ],
          })
        );
        return;
      }
      res.writeHead(200);
      res.end(JSON.stringify({ checkouts: [] }));
      return;
    }

    res.writeHead(404);
    res.end('{}');
  });

  await new Promise<void>((resolve) => fakeServer.listen(0, '127.0.0.1', resolve));
  const apiUrl = `http://127.0.0.1:${(fakeServer.address() as { port: number }).port}`;

  const { config, repository, whatsapp } = createPrivacyTestSetup();
  try {
    const depix = new DePixAppProvider({
      apiUrl,
      apiKey: 'sk_live_batch_watcher_test_key_123456',
      webhookSecret: 'sec',
    });
    const depixConfig: AppConfig = { ...config, cryptoProvider: 'depixapp' };
    const engine = new ConversationEngine(depixConfig, repository, depix, whatsapp);
    const watcher = new ExpirationWatcher(repository, whatsapp, 3, engine);

    // Cria 4 cobranças vencidas + 1 cobrança no rail Liquid dentro da grace window de 15 min
    for (let i = 1; i <= 4; i++) {
      repository.createOrder({
        id: `id_batch_${i}`,
        externalId: `ext_batch_${i}`,
        provider: 'depixapp',
        providerChargeId: `prd_batch_${i}`,
        customerPhone: `551191111000${i}`,
        amountBrl: 50,
        cryptoAsset: 'DEPIX',
        cryptoNetwork: 'LIQUID',
        walletAddress: 'Liquid',
        pixCopyPaste: `https://pay.depixapp.com/c/prd_batch_${i}`,
        status: 'PENDING',
        warningSent: false,
        createdAt: basePastIso,
        expiresAt: basePastIso,
      });
    }

    repository.createOrder({
      id: 'id_grace',
      externalId: 'ext_grace',
      provider: 'depixapp',
      providerChargeId: 'prd_grace_rail',
      customerPhone: '5511911110099',
      amountBrl: 75,
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      walletAddress: 'Liquid',
      pixCopyPaste: 'https://pay.depixapp.com/c/prd_grace_rail',
      status: 'PENDING',
      warningSent: false,
      createdAt: basePastIso,
      expiresAt: basePastIso,
    });

    // 1. Durante erro HTTP 503 na API, NENHUMA cobrança é expirada às cegas!
    const sweepDuringOutage = await watcher.sweepPendingOrders(new Date());
    assert.equal(sweepDuringOutage.expiredCount, 0);
    assert.equal(repository.getOrderById('id_batch_1')?.status, 'PENDING');

    // 2. API volta ao normal: varreduras subsequentes expiram E desativam 100% das 4 cobranças sem perder nenhuma,
    //    enquanto `prd_grace_rail` é estendida pela grace window de 15 min e continua PENDING!
    return503 = false;
    let clock = Date.now() + 20_000;
    for (let cycle = 0; cycle < 4; cycle++) {
      clock += 20_000;
      await watcher.sweepPendingOrders(new Date(clock));
    }

    for (let i = 1; i <= 4; i++) {
      const ord = repository.getOrderById(`id_batch_${i}`);
      assert.equal(ord?.status, 'EXPIRED');
      assert.equal(ord?.remoteDeactivated, true);
      assert.equal(deactivatedIds.includes(`prd_batch_${i}`), true);
    }

    const graceOrd = repository.getOrderById('id_grace');
    assert.equal(graceOrd?.status, 'PENDING');
    assert.equal(deactivatedIds.includes('prd_grace_rail'), false);

    // 2b. Anti-starvation: mesmo com 25 vendas históricas retidas em PIX_CONFIRMED no Cofre,
    //     um pedido PENDING ao vivo é priorizado e confirmado já na próxima varredura de 15s!
    for (let v = 1; v <= 25; v++) {
      repository.createOrder({
        id: `id_vault_${v}`,
        externalId: `ext_vault_${v}`,
        provider: 'depixapp',
        providerChargeId: `prd_vault_${v}`,
        customerPhone: `55119444400${String(v).padStart(2, '0')}`,
        amountBrl: 60,
        cryptoAsset: 'DEPIX',
        cryptoNetwork: 'LIQUID',
        walletAddress: 'Liquid',
        pixCopyPaste: `https://pay.depixapp.com/c/prd_vault_${v}`,
        status: 'PIX_CONFIRMED',
        warningSent: false,
        createdAt: basePastIso,
        expiresAt: basePastIso,
      });
    }
    repository.createOrder({
      id: 'id_live_prio',
      externalId: 'ext_live_prio',
      provider: 'depixapp',
      providerChargeId: 'prd_live_priority',
      customerPhone: '5511955556666',
      amountBrl: 110,
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      walletAddress: 'Liquid',
      pixCopyPaste: 'https://pay.depixapp.com/c/prd_live_priority',
      status: 'PENDING',
      warningSent: false,
      createdAt: new Date(clock).toISOString(),
      expiresAt: new Date(clock + 900_000).toISOString(),
    });
    clock += 20_000;
    await watcher.sweepPendingOrders(new Date(clock));
    assert.equal(repository.getOrderById('id_live_prio')?.status, 'PIX_CONFIRMED');

    // 3. PIX_CONFIRMED -> FAILED (PAYER_MISMATCH) chama /deactivate e marca remoteDeactivated = true!
    repository.createOrder({
      id: 'id_mismatch',
      externalId: 'ext_mismatch',
      provider: 'depixapp',
      providerChargeId: 'prd_mismatch_1',
      customerPhone: '5511911110088',
      amountBrl: 90,
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      walletAddress: 'Liquid',
      pixCopyPaste: 'https://pay.depixapp.com/c/prd_mismatch_1',
      status: 'PENDING',
      warningSent: false,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    });
    await engine.handleSettlementWebhook({
      provider: 'depixapp',
      externalId: 'ext_mismatch',
      newStatus: 'PIX_CONFIRMED',
      rawEventName: 'checkout.processing',
    });
    assert.equal(repository.getOrderById('id_mismatch')?.remoteDeactivated, false);
    await engine.handleSettlementWebhook({
      provider: 'depixapp',
      externalId: 'ext_mismatch',
      newStatus: 'FAILED',
      rawEventName: 'checkout.cancelled',
    });
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(deactivatedIds.includes('prd_mismatch_1'), true);
    assert.equal(repository.getOrderById('id_mismatch')?.remoteDeactivated, true);

    // 4. Corrida AWAITING_ACTIVE_ORDER_DECISION + expiração simultânea preserva pendingNewAmountBrl (gera R$ 80, não R$ 2!)
    const racePhone = '5511922223333';
    const soonPastIso = new Date(Date.now() + 5_000).toISOString();
    repository.createOrder({
      id: 'id_menu_race',
      externalId: 'ext_menu_race',
      provider: 'depixapp',
      providerChargeId: 'prd_menu_race',
      customerPhone: racePhone,
      amountBrl: 50,
      cryptoAsset: 'DEPIX',
      cryptoNetwork: 'LIQUID',
      walletAddress: 'Liquid',
      pixCopyPaste: 'https://pay.depixapp.com/c/prd_menu_race',
      status: 'PENDING',
      warningSent: false,
      createdAt: basePastIso,
      expiresAt: soonPastIso,
    });
    await engine.handleIncomingMessage({ phone: racePhone, text: 'Pix de 80' });
    assert.equal(repository.getSession(racePhone).stage, 'AWAITING_ACTIVE_ORDER_DECISION');
    assert.equal(repository.getSession(racePhone).pendingNewAmountBrl, 80);

    // Expira a cobrança de R$ 50 antes de o cliente digitar "2" (avança janela simulada de 2 min)
    DePixAppProvider.clearRateLimitWindows();
    await watcher.sweepPendingOrders(new Date(clock + 120_000));
    assert.equal(repository.getOrderById('id_menu_race')?.status, 'EXPIRED');
    assert.equal(repository.getSession(racePhone).stage, 'AWAITING_AMOUNT');
    assert.equal(repository.getSession(racePhone).pendingNewAmountBrl, 80);

    // Troca para MockProvider só para testar a geração de R$ 80 e corrida de snapshot em createCharge
    const mockProv = new MockProvider({ webhookSecret: 'sec' });
    engine.updateRuntimeAccount({ ...config, cryptoProvider: 'mock' }, mockProv);
    await engine.handleIncomingMessage({ phone: racePhone, text: '2' });
    const afterTwo = repository.findMostRecentOrderByPhone(racePhone);
    assert.equal(afterTwo?.amountBrl, 80);
    // 5. Normalização UTC de expiresAt com offset -03:00 funciona na comparação lexicográfica do SQLite!
    repository.createOrder({
      id: 'ord_tz_offset',
      externalId: 'ext_tz_offset',
      provider: 'hodle',
      providerChargeId: 'dep_tz_1',
      customerPhone: '5511933334444',
      amountBrl: 100,
      cryptoAsset: 'USDT',
      cryptoNetwork: 'POLYGON',
      walletAddress: '0x123',
      pixCopyPaste: '000201...',
      status: 'PENDING',
      warningSent: false,
      createdAt: '2026-11-16T17:00:00.000Z',
      expiresAt: '2026-11-16T14:15:00-03:00',
    });
    const activeTz = repository.findActivePendingOrderByPhone(
      '5511933334444',
      '2026-11-16T17:00:00.000Z'
    );
    assert.equal(activeTz?.id, 'ord_tz_offset');
    assert.equal(activeTz?.expiresAt, '2026-11-16T17:15:00.000Z');

    // 6. Se uma cobrança antiga venceu há 2s e o cliente já gerou uma nova cobrança ativa antes da varredura,
    //    o ExpirationWatcher expira a antiga silenciosamente SEM mandar falso alerta de expiração embaixo do novo QR!
    const supersededPhone = '5511966667777';
    repository.createOrder({
      id: 'ord_superseded_old',
      externalId: 'ext_superseded_old',
      provider: 'mock',
      providerChargeId: 'mock_old_1',
      customerPhone: supersededPhone,
      amountBrl: 50,
      cryptoAsset: 'USDT',
      cryptoNetwork: 'POLYGON',
      walletAddress: '0x123',
      pixCopyPaste: '000201OLD',
      status: 'PENDING',
      warningSent: false,
      createdAt: new Date(Date.now() - 960_000).toISOString(),
      expiresAt: new Date(Date.now() - 2_000).toISOString(),
    });
    await engine.handleIncomingMessage({ phone: supersededPhone, text: 'Pix de 50' });
    const msgsBeforeSweep = repository.listMessages(supersededPhone).length;
    await watcher.sweepPendingOrders(new Date());
    assert.equal(repository.getOrderById('ord_superseded_old')?.status, 'EXPIRED');
    const msgsAfterSweep = repository.listMessages(supersededPhone);
    assert.equal(msgsAfterSweep.length, msgsBeforeSweep);

    // 7. Após expiração e passagem de tempo (>5 min) ou mensagem genérica "Quero fazer um novo pix",
    //    NÃO ressuscita valor antigo pendente sem o cliente ter informado valor!
    const stalePhone = '5511977778888';
    repository.createOrder({
      id: 'ord_stale_menu',
      externalId: 'ext_stale_menu',
      provider: 'mock',
      providerChargeId: 'mock_stale_1',
      customerPhone: stalePhone,
      amountBrl: 50,
      cryptoAsset: 'USDT',
      cryptoNetwork: 'POLYGON',
      walletAddress: '0x123',
      pixCopyPaste: '000201STALE',
      status: 'PENDING',
      warningSent: false,
      createdAt: basePastIso,
      expiresAt: new Date(Date.now() + 10_000).toISOString(),
    });
    await engine.handleIncomingMessage({ phone: stalePhone, text: 'Pix de 80' });
    await watcher.sweepPendingOrders(new Date(Date.now() + 20 * 60_000));
    const ordersBeforeStaleMsg = repository.listRecentOrders().length;
    await engine.handleIncomingMessage({
      phone: stalePhone,
      text: 'Bom dia! Quero fazer um novo pix',
    });
    assert.equal(repository.listRecentOrders().length, ordersBeforeStaleMsg);

    // 8. Isolamento de provedor em findOrderByWebhookIds por externalId!
    assert.equal(
      repository.findOrderByWebhookIds({ provider: 'mock', externalId: 'ext_tz_offset' }),
      null
    );
    assert.equal(
      repository.findOrderByWebhookIds({ provider: 'hodle', externalId: 'ext_tz_offset' })?.id,
      'ord_tz_offset'
    );
  } finally {
    fakeServer.close();
    repository.close();
  }
});
