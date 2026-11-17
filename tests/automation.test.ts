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
  hasUnparsedDigitsInMenuReply,
  isCancelCommand,
  isExitCommand,
  isHelpCommand,
  isPaymentConfirmationMessage,
  isPostOrderFollowUpMessage,
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
});

test('NLU avançado: cripto/moedas, logradouros, estornos, horários coloquiais, unidades, BRCode EMV e fronteiras Unicode', () => {
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

  // Cobertura Busca #22: "Saiu 50 reais da minha conta", enumerações por extenso ("dias dez e quinze", "kits cinco e seis"),
  // horários com "umas" / "meio-dia" / "meia-noite" e especificações/unidades físicas ("tamanho 42", "aro 15", "10 hectares", "5 toneladas", "500 mega")
  assert.equal(isStatusQueryMessage('Saiu 50 reais da minha conta'), true);
  assert.equal(isPaymentConfirmationMessage('Saiu 50 reais da minha conta'), true);
  assert.equal(isStatusQueryMessage('Já saiu R$ 50,00 da conta'), true);
  assert.equal(isStatusQueryMessage('Saiu os 50 da minha conta mas não confirmou'), true);
  assert.equal(parseBrlAmountFromText('Saiu 50 reais da minha conta'), null);

  assert.equal(parseBrlAmountFromText('Vou pagar no pix nos dias dez e quinze'), null);
  assert.equal(parseBrlAmountFromText('Quero os kits cinco e seis no pix'), null);
  assert.equal(parseBrlAmountFromText('Mesas dez e doze vão pagar no pix'), null);
  assert.equal(parseBrlAmountFromText('pix de dois e três'), null);
  assert.equal(parseBrlAmountFromText('pix de cinco e seis centavos'), 5.06);

  assert.equal(parseBrlAmountFromText('Te mando o pix umas 10'), null);
  assert.equal(parseBrlAmountFromText('Te mando o pix umas duas e trinta'), null);
  assert.equal(parseBrlAmountFromText('Meio-dia e trinta mando o pix'), null);
  assert.equal(parseBrlAmountFromText('Meia-noite e vinte mando o pix'), null);
  assert.equal(parseBrlAmountFromText('Meio dia e quinze mando o pix'), null);

  assert.equal(parseBrlAmountFromText('Camisa tamanho 42 no pix'), null);
  assert.equal(parseBrlAmountFromText('Pneu aro 15 no pix'), null);
  assert.equal(parseBrlAmountFromText('Terreno de 10 hectares no pix'), null);
  assert.equal(parseBrlAmountFromText('Caminhão de 5 toneladas no pix'), null);
  assert.equal(parseBrlAmountFromText('Internet de 500 mega no pix'), null);
  assert.equal(parseBrlAmountFromText('Celular 128 gb no pix'), null);
  assert.equal(parseBrlAmountFromText('Fonte 500w 220v no pix'), null);
  assert.equal(parseBrlAmountFromText('Bateria 60Ah no pix'), null);
  assert.equal(parseBrlAmountFromText('Camisa tam. 42, manda um pix de 80'), 80);

  // Cobertura Busca #23: estornos/devoluções no pretérito/particípio, novos pedidos com artigo/feminino/"preciso de",
  // "TV"/"largo por 100", linha digitável FEBRABAN, "nota fiscal"/"nf-e"/"comanda"/"cupom"/"contrato", polegadas 27", 2:30pm, tether e "100 reais em BTC"
  assert.equal(isStatusQueryMessage('O banco estornou meu pix de 50, por quê?'), true);
  assert.equal(parseBrlAmountFromText('O banco estornou meu pix de 50, por quê?'), null);
  assert.equal(isStatusQueryMessage('Estornou os 50 reais do pix'), true);
  assert.equal(parseBrlAmountFromText('Estornou os 50 reais do pix'), null);
  assert.equal(isStatusQueryMessage('O pix de 50 foi estornado'), true);
  assert.equal(parseBrlAmountFromText('O pix de 50 foi estornado'), null);
  assert.equal(isStatusQueryMessage('O pix de 50 foi devolvido'), true);
  assert.equal(parseBrlAmountFromText('O pix de 50 foi devolvido'), null);
  assert.equal(isStatusQueryMessage('Reembolsou o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Reembolsou o pix de 50'), null);
  assert.equal(isStatusQueryMessage('O pix de 50 voltou pra minha conta'), true);
  assert.equal(parseBrlAmountFromText('O pix de 50 voltou pra minha conta'), null);
  assert.equal(isStatusQueryMessage('Retornou os 50 reais pra minha conta'), true);
  assert.equal(isStatusQueryMessage('Foi estornado!'), true);
  assert.equal(isStatusQueryMessage('Deu falha no pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Deu falha no pix de 50'), null);

  assert.equal(isStatusQueryMessage('Deu erro antes, gera um novo pix de 80'), false);
  assert.equal(parseBrlAmountFromText('Deu erro antes, gera um novo pix de 80'), 80);
  assert.equal(isPaymentConfirmationMessage('Já fiz aquele pix, agora preciso de outro de 100'), false);
  assert.equal(parseBrlAmountFromText('Já fiz aquele pix, agora preciso de outro de 100'), 100);
  assert.equal(isStatusQueryMessage('Faz uma nova cobrança de 100'), false);
  assert.equal(isPaymentConfirmationMessage('Faz uma nova cobrança de 100'), false);
  assert.equal(parseBrlAmountFromText('Faz uma nova cobrança de 100'), 100);

  assert.equal(parseBrlAmountFromText('Pix do conserto da TV 250'), 250);
  assert.equal(parseBrlAmountFromText('Pix da TV nova 1500'), 1500);
  assert.equal(parseBrlAmountFromText('Manda o pix da TV, 500'), 500);
  assert.equal(parseBrlAmountFromText('Eu largo por 100 no pix'), 100);
  assert.equal(parseBrlAmountFromText('Moro na Tv. das Acácias, 45, manda o pix'), null);
  assert.equal(parseBrlAmountFromText('Moro no Largo da Batata, 50, aceita pix?'), null);

  assert.equal(
    parseBrlAmountFromText(
      'Pagar boleto 34191.79001 01043.510047 91020.150008 5 89990000015000 no pix'
    ),
    null
  );
  assert.equal(parseBrlAmountFromText('Quero pagar a nota fiscal 1234 no pix'), null);
  assert.equal(parseBrlAmountFromText('Nota fiscal 1234, manda pix de 300'), 300);
  assert.equal(parseBrlAmountFromText('NF-e 1234 no pix'), null);
  assert.equal(parseBrlAmountFromText('Comanda 18 no pix'), null);
  assert.equal(parseBrlAmountFromText('Cupom 50 no pix'), null);
  assert.equal(parseBrlAmountFromText('Contrato 1200 no pix'), null);
  assert.equal(parseBrlAmountFromText('Matrícula 2040 no pix'), null);

  assert.equal(parseBrlAmountFromText('Monitor 27" no pix'), null);
  assert.equal(parseBrlAmountFromText('Notebook 15,6" no pix'), null);
  assert.equal(parseBrlAmountFromText('Roda 17\'\' no pix'), null);
  assert.equal(parseBrlAmountFromText('Ele pediu "pix de 50"'), 50);
  assert.equal(parseBrlAmountFromText('Te mando o pix 2:30pm'), null);
  assert.equal(parseBrlAmountFromText('Te mando o pix 10am'), null);

  assert.equal(parseBrlAmountFromText('50 tether no pix'), null);
  assert.equal(parseBrlAmountFromText('Quanto dá 100 reais em BTC no pix?'), null);
  assert.equal(parseBrlAmountFromText('Quero converter 100 reais em USDT'), null);

  // Cobertura Busca #24: emojis keycap 1️⃣/2️⃣ no menu, falsos positivos em status/passei vs novos pedidos,
  // L-BTC e cotações ("O dólar tá 5,80"), contáveis/modelos/limites/BRCode EMV/Erro 404/conta corrente, retenção/análise/agendamento
  assert.deepEqual(parseActiveOrderMenuReply('1️⃣'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2️⃣'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2️⃣ gerar 80'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 80,
  });
  assert.equal(parseBrlAmountFromText('Passo 5️⃣ do pix'), null);

  assert.equal(isStatusQueryMessage('Meu pedido chegou, pix de 120 por favor'), false);
  assert.equal(parseBrlAmountFromText('Meu pedido chegou, pix de 120 por favor'), 120);
  assert.equal(isStatusQueryMessage('Meu salário caiu hoje, pix de 200'), false);
  assert.equal(parseBrlAmountFromText('Meu salário caiu hoje, pix de 200'), 200);
  assert.equal(isStatusQueryMessage('Entrou dinheiro na conta, pix de 80'), false);
  assert.equal(parseBrlAmountFromText('Entrou dinheiro na conta, pix de 80'), 80);
  assert.equal(isPaymentConfirmationMessage('Passei na loja hoje, me cobra 50 no pix'), false);
  assert.equal(parseBrlAmountFromText('Passei na loja hoje, me cobra 50 no pix'), 50);
  assert.equal(isPaymentConfirmationMessage('Passei aí mais cedo, pix de 80 por favor'), false);
  assert.equal(parseBrlAmountFromText('Passei aí mais cedo, pix de 80 por favor'), 80);
  assert.equal(isPaymentConfirmationMessage('Já paguei aquele, agora cobra 80 no pix'), false);
  assert.equal(parseBrlAmountFromText('Já paguei aquele, agora cobra 80 no pix'), 80);
  assert.equal(isStatusQueryMessage('Deu erro antes, quero trocar pra 80 no pix'), false);
  assert.equal(parseBrlAmountFromText('Deu erro antes, quero trocar pra 80 no pix'), 80);
  assert.equal(isStatusQueryMessage('Estornou aquele, muda pra 50 no pix'), false);
  assert.equal(parseBrlAmountFromText('Estornou aquele, muda pra 50 no pix'), 50);
  assert.equal(isStatusQueryMessage('Deu erro no outro, faz um de 50'), false);
  assert.equal(parseBrlAmountFromText('Deu erro no outro, faz um de 50'), 50);

  assert.equal(parseBrlAmountFromText('Quanto dá 100 reais em L-BTC no pix?'), null);
  assert.equal(parseBrlAmountFromText('O dólar tá 5,80 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Dólar hoje a R$ 5,80 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Cotação do USDT tá 5,85 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Euro está 6,20 no pix?'), null);

  assert.equal(parseBrlAmountFromText('Comprei 10 camisas, quanto fica no pix?'), null);
  assert.equal(parseBrlAmountFromText('Quero 6 garrafas, aceita pix?'), null);
  assert.equal(parseBrlAmountFromText('Quero pagar 5 faturas no pix'), null);
  assert.equal(parseBrlAmountFromText('Tenho 5 dúvidas sobre o pix'), null);
  assert.equal(parseBrlAmountFromText('Qual o limite do pix? 5000?'), null);
  assert.equal(parseBrlAmountFromText('O pix mínimo é 5 reais?'), null);
  assert.equal(parseBrlAmountFromText('Quero comprar o iPhone 15 no pix'), null);
  assert.equal(parseBrlAmountFromText('Tem PlayStation 5 no pix?'), null);
  assert.equal(
    parseBrlAmountFromText(
      'Posso pagar esse pix 00020126580014br.gov.bcb.pix0136123e4567-e89b-12d3-a456-426614174000520400005303986540585.005802BR5912LOJA 24 LTDA6009SAO PAULO62070503***630412AB'
    ),
    null
  );
  assert.equal(parseBrlAmountFromText('Erro 404 no link do pix'), null);
  assert.equal(isStatusQueryMessage('Erro 404 no link do pix'), true);
  assert.equal(parseBrlAmountFromText('Erro 500 ao abrir o pix'), null);
  assert.equal(parseBrlAmountFromText('Pix na conta corrente 12345'), null);

  assert.equal(parseBrlAmountFromText('Não concluiu o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Não concluiu o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Não finalizou o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Deu saldo insuficiente no pix de 50'), null);
  assert.equal(isStatusQueryMessage('Deu saldo insuficiente no pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Estourou meu limite no pix de 500'), null);
  assert.equal(parseBrlAmountFromText('Travou o app do banco no pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Meu pix de 50 ficou em análise no banco'), null);
  assert.equal(isStatusQueryMessage('Meu pix de 50 ficou em análise no banco'), true);
  assert.equal(parseBrlAmountFromText('O banco segurou meu pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Agendei o pix de 50 sem querer'), null);
  assert.equal(isStatusQueryMessage('Agendei o pix de 50 sem querer'), true);
  assert.equal(parseBrlAmountFromText('Pix agendado de R$ 50,00'), null);

  // Cobertura Busca #25: fronteiras Unicode (tá/está/dá/é/mãe/média), negações no pretérito + falhas de link/QR,
  // whitelist estrita pós-verbo em isPaymentConfirmationMessage e ordinais 1ª/2ª/1º/2º no menu 1 / 2
  assert.equal(isPaymentConfirmationMessage('Ainda não está pago o pix de 50'), false);
  assert.equal(isPaymentConfirmationMessage('Não tá pago o pix de 50'), false);
  assert.equal(parseBrlAmountFromText('Ainda não está pago o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Quanto tá o corte no pix? 50?'), null);
  assert.equal(parseBrlAmountFromText('Quanto está a consulta no pix? 200?'), null);
  assert.equal(parseBrlAmountFromText('Quanto dá com entrega no pix? 80?'), null);
  assert.equal(parseBrlAmountFromText('É o limite do pix 5000?'), null);
  assert.equal(parseBrlAmountFromText('Qual é o máximo no pix? 6000?'), null);
  assert.equal(parseBrlAmountFromText('Qual é o mínimo no pix? 5?'), null);
  assert.equal(parseBrlAmountFromText('Quanto é o mínimo? 10 reais no pix?'), null);
  assert.equal(isStatusQueryMessage('O pix de 50 deu erro, minha mãe faz amanhã'), true);
  assert.equal(parseBrlAmountFromText('O pix de 50 deu erro, minha mãe faz amanhã'), null);
  assert.equal(parseBrlAmountFromText('Deu erro no app, minha mãe manda os 50 reais depois'), null);
  assert.equal(parseBrlAmountFromText('Média 15 no pix'), 15);

  assert.equal(parseBrlAmountFromText('Não paguei o pix de 50 ainda'), null);
  assert.equal(parseBrlAmountFromText('Ainda não fiz o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não mandei os 50 no pix ainda'), null);
  assert.equal(parseBrlAmountFromText('Ainda não foi pago o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Paguei não, quero um pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Não consegui abrir o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Não consegui abrir o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('O link do pix de 50 não abriu'), null);
  assert.equal(isStatusQueryMessage('O link do pix de 50 não abriu'), true);
  assert.equal(parseBrlAmountFromText('O QR Code de 50 não funciona'), null);
  assert.equal(isStatusQueryMessage('O QR Code de 50 não funciona'), true);
  assert.equal(parseBrlAmountFromText('Link do pix de 50 deu inválido'), null);

  assert.equal(isPaymentConfirmationMessage('Fiz as contas aqui e deu 50 no pix'), false);
  assert.equal(parseBrlAmountFromText('Fiz as contas aqui e deu 50 no pix'), 50);
  assert.equal(isPaymentConfirmationMessage('Fiz a soma e deu 120 no pix'), false);
  assert.equal(parseBrlAmountFromText('Fiz a soma e deu 120 no pix'), 120);
  assert.equal(isPaymentConfirmationMessage('Mandei os dados aqui pro pix de 50'), false);
  assert.equal(parseBrlAmountFromText('Mandei os dados aqui pro pix de 50'), 50);
  assert.equal(isPaymentConfirmationMessage('Mandei mensagem antes querendo pix de 50'), false);
  assert.equal(parseBrlAmountFromText('Mandei mensagem antes querendo pix de 50'), 50);
  assert.equal(isPaymentConfirmationMessage('Fiz as contas aqui e deu 50'), false);

  assert.deepEqual(parseActiveOrderMenuReply('1ª opção'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2ª opção'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Quero a 2ª'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2º item, gerar 80'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 80,
  });

  assert.equal(formatTimeSaoPaulo('2026-07-01T18:15:00.000Z'), '15:15');
});

test('NLU Busca #26: infinitivos subordinados, cancelamentos/tentativas/negações plurais, perguntas diretas de preço, cotações telegráficas e menu "Manda a 1"', () => {
  // Achado 1: orações subordinadas ("ao fazer", "pra gerar", "para enviar", "na hora de fazer", "se eu quiser fazer")
  assert.equal(isStatusQueryMessage('Deu erro ao fazer o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Deu erro ao fazer o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Deu problema para enviar o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Deu problema para enviar o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Meu banco recusou na hora de fazer o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Meu banco recusou na hora de fazer o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Qual o mínimo pra fazer pix? 5?'), null);
  assert.equal(parseBrlAmountFromText('Qual o limite para gerar um pix? 5000?'), null);
  assert.equal(parseBrlAmountFromText('Quanto custa pra fazer um pix de 50?'), null);
  assert.equal(parseBrlAmountFromText('Tem taxa pra gerar um pix de 100?'), null);
  assert.equal(parseBrlAmountFromText('Se eu quiser fazer um pix de 50 tem taxa?'), null);

  // Achado 2: cancelamentos no pretérito/passiva, tentativas frustradas ("tentei", "deu errado", "quase fiz") e negações plurais/passivas
  assert.equal(isStatusQueryMessage('Por que meu pix de 50 foi cancelado?'), true);
  assert.equal(parseBrlAmountFromText('Por que meu pix de 50 foi cancelado?'), null);
  assert.equal(isStatusQueryMessage('O pix de 50 foi cancelado'), true);
  assert.equal(parseBrlAmountFromText('O pix de 50 foi cancelado'), null);
  assert.equal(isStatusQueryMessage('O banco cancelou meu pix de 50'), true);
  assert.equal(parseBrlAmountFromText('O banco cancelou meu pix de 50'), null);
  assert.equal(isStatusQueryMessage('Minha cobrança de 50 apareceu cancelada'), true);
  assert.equal(parseBrlAmountFromText('Minha cobrança de 50 apareceu cancelada'), null);
  assert.equal(isStatusQueryMessage('Tentei pagar o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Tentei pagar o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Tentei fazer o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Tentei fazer o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Deu errado o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Deu errado o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não deu certo o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Os 50 reais não caíram ainda no pix'), true);
  assert.equal(parseBrlAmountFromText('Os 50 reais não caíram ainda no pix'), null);
  assert.equal(isStatusQueryMessage('Os 50 reais não foram aprovados no pix'), true);
  assert.equal(parseBrlAmountFromText('Os 50 reais não foram aprovados no pix'), null);
  assert.equal(parseBrlAmountFromText('O pix de 50 não compensou'), null);
  assert.equal(parseBrlAmountFromText('Não está confirmado o pix de 50'), null);
  assert.equal(isPaymentConfirmationMessage('Quase fiz o pix de 50'), false);
  assert.equal(parseBrlAmountFromText('Quase fiz o pix de 50'), null);

  // Achado 3: perguntas diretas de preço/valor e faixas ("Custa R$ 50 no pix?", "Fica 80 no pix?", "a partir de 5?")
  assert.equal(parseBrlAmountFromText('Custa R$ 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Fica 80 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Sai por 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Tá 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Está R$ 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('O valor é 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('O valor é 50 no pix'), 50);
  assert.equal(parseBrlAmountFromText('Posso pagar R$ 50 no pix?'), 50);
  assert.equal(parseBrlAmountFromText('Qual o preço no pix? 50?'), null);
  assert.equal(parseBrlAmountFromText('Qual o valor no pix? 50?'), null);
  assert.equal(parseBrlAmountFromText('Aceita pix a partir de 5?'), null);
  assert.equal(parseBrlAmountFromText('Posso fazer pix acima de 5000?'), null);
  assert.equal(parseBrlAmountFromText('Aceita pix abaixo de 10?'), null);

  // Achado 4: cotações telegráficas sem verbo de ligação
  assert.equal(parseBrlAmountFromText('Dólar comercial 5,80 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Dólar hoje 5,80 no pix'), null);
  assert.equal(parseBrlAmountFromText('Euro comercial R$ 6,20 no pix'), null);
  assert.equal(parseBrlAmountFromText('Bitcoin hoje 5 mil no pix'), null);

  // Achado 5: menu 1 / 2 com "Manda a 1", "Envia a 1", "Gera a 2", "Faz a 2" sem capturar "Manda 2 mil"
  assert.deepEqual(parseActiveOrderMenuReply('Manda a 1'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Envia a 1'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Gera a 2'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Faz a 2'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Manda 2 mil'), {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: 2000,
  });

  // Cobertura Busca #27: débito passivo/duplicidade, infinitivos após impossibilidade/gerúndio/"na análise",
  // perguntas diretas/indiretas de preço/desconto/juro/limite, "100 reais de BTC/USDT" (permitindo depix) e menu "Vou na 1"/"Pode mandar a 1"/"2 - Cancelar a atual, quero R$ 80"
  assert.equal(isStatusQueryMessage('Foi debitado 50 reais da minha conta'), true);
  assert.equal(isPaymentConfirmationMessage('Foi debitado 50 reais da minha conta'), true);
  assert.equal(parseBrlAmountFromText('Foi debitado 50 reais da minha conta'), null);
  assert.equal(isStatusQueryMessage('Foram descontados 50 reais da minha conta'), true);
  assert.equal(parseBrlAmountFromText('Foi descontado R$ 50,00 da minha conta no pix'), null);
  assert.equal(isStatusQueryMessage('Cobrou 2 vezes o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Cobrou 2 vezes o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Cobraram duas vezes o pix de 50'), null);

  assert.equal(isStatusQueryMessage('Não deu certo fazer o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Não deu certo fazer o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Não foi possível fazer o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Não foi possível fazer o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não estou conseguindo fazer o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Não tô conseguindo pagar o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Meu banco não deixou fazer o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Meu banco não deixou fazer o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Não foi autorizado o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Não foi autorizado o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Não liberou o pix de 50 no meu banco'), true);
  assert.equal(parseBrlAmountFromText('Não liberou o pix de 50 no meu banco'), null);
  assert.equal(isStatusQueryMessage('Estou tentando pagar o pix de 50 e não vai'), true);
  assert.equal(parseBrlAmountFromText('Estou tentando pagar o pix de 50 e não vai'), null);
  assert.equal(isStatusQueryMessage('Fui pagar o pix de 50 e o app fechou'), true);
  assert.equal(parseBrlAmountFromText('Fui pagar o pix de 50 e o app fechou'), null);
  assert.equal(isStatusQueryMessage('Meu pix de 50 caiu na análise do banco'), true);
  assert.equal(parseBrlAmountFromText('Meu pix de 50 caiu na análise do banco'), null);

  assert.equal(parseBrlAmountFromText('Quanto é no pix? 50?'), null);
  assert.equal(parseBrlAmountFromText('Quanto é o frete no pix? 20?'), null);
  assert.equal(parseBrlAmountFromText('O mínimo pra pagar no pix é 10?'), null);
  assert.equal(parseBrlAmountFromText('O máximo para pagar no pix é 5000?'), null);
  assert.equal(parseBrlAmountFromText('O limite para pagar no pix é 2000?'), null);
  assert.equal(parseBrlAmountFromText('O limite pra transferir no pix é 1000?'), null);
  assert.equal(parseBrlAmountFromText('Pix de 50 tem desconto?'), null);
  assert.equal(parseBrlAmountFromText('R$ 50 no pix tem desconto?'), null);
  assert.equal(parseBrlAmountFromText('Pagando 100 no pix ganha desconto?'), null);
  assert.equal(parseBrlAmountFromText('Tem juro no pix de 100?'), null);
  assert.equal(parseBrlAmountFromText('É 50 reais no pix?'), null);
  assert.equal(parseBrlAmountFromText('Seria 50 reais no pix?'), null);
  assert.equal(parseBrlAmountFromText('Faz por 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Quero saber se custa 50 no pix'), null);
  assert.equal(parseBrlAmountFromText('Queria saber se fica 80 no pix'), null);
  assert.equal(parseBrlAmountFromText('Me diz se o valor é 50 no pix'), null);
  assert.equal(parseBrlAmountFromText('Me confirma se o preço é 100 no pix'), null);
  assert.equal(parseBrlAmountFromText('Sabe dizer se fica 80 no pix'), null);

  assert.equal(parseBrlAmountFromText('Comprar 100 reais de BTC no pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 100 reais de USDT no pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 100 reais de dólares no pix'), null);
  assert.equal(parseBrlAmountFromText('Quero 50 reais de depix no pix'), 50);

  assert.deepEqual(parseActiveOrderMenuReply('Pode mandar a 1'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Pode gerar a 2'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Vou na 1'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Vou de 2'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2 - Cancelar a atual, quero R$ 80'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 80,
  });
  assert.equal(parseBrlAmountFromText('Cancela a atual, gera um pix de 80'), 80);
  assert.equal(parseBrlAmountFromText('Cancela, quero um pix de 80'), 80);
});

test('NLU Busca #28: CEP/conta hifenizados com pontuação, particípios/gerúndios negados, problemas/processamento/duplicidade, "quanto" posposto e menu "2, 80" / "Quero a 2 de 80"', () => {
  // Achado 1: CEP, conta/agência hifenizada ou código multi-hífen seguidos de vírgula ou ponto final
  assert.equal(parseBrlAmountFromText('Entrega no CEP 01310-100, manda o pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('CEP 01310-100. Pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Conta 56789-0, manda pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Código 123-456-789, manda pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('pix de R$ 50,00-10,00'), null);

  // Achado 2: negações participiais sem auxiliar, gerúndios negativos, "não foi" e "negou"/"rejeitou"
  assert.equal(isStatusQueryMessage('Apareceu transação não autorizada no pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Apareceu transação não autorizada no pix de 50'), null);
  assert.equal(isStatusQueryMessage('Pagamento não autorizado de R$ 50 no pix'), true);
  assert.equal(parseBrlAmountFromText('Pagamento não autorizado de R$ 50 no pix'), null);
  assert.equal(isStatusQueryMessage('Pix de 50 não aprovado pelo banco'), true);
  assert.equal(parseBrlAmountFromText('Pix de 50 não aprovado pelo banco'), null);
  assert.equal(parseBrlAmountFromText('Pix de 50 não confirmado'), null);
  assert.equal(parseBrlAmountFromText('Pix de 50 não concluído'), null);
  assert.equal(parseBrlAmountFromText('Pix de 50 não compensado'), null);
  assert.equal(isStatusQueryMessage('O banco não está aprovando o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('O banco não está aprovando o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Não tá passando o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Não tá passando o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Meu pix de 50 não foi'), true);
  assert.equal(parseBrlAmountFromText('Meu pix de 50 não foi'), null);
  assert.equal(isStatusQueryMessage('Não foi o pix de 50'), true);
  assert.equal(isStatusQueryMessage('Meu banco negou o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Meu banco negou o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Pix de 50 negado pelo banco'), null);
  assert.equal(isStatusQueryMessage('Rejeitou na hora de mandar o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Rejeitou na hora de mandar o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Transação rejeitada no pix de 50'), null);

  // Achado 3: "problema" (preservando "sem problema"), "em processamento"/"pendente", "retendo"/"retenção" e duplicidade flexível
  assert.equal(isStatusQueryMessage('Tive problema na hora de pagar os 50 no pix'), true);
  assert.equal(parseBrlAmountFromText('Tive problema na hora de pagar os 50 no pix'), null);
  assert.equal(isStatusQueryMessage('Tive um problema com o pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Tive um problema com o pix de 50'), null);
  assert.equal(isStatusQueryMessage('Está dando problema no pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Está dando problema no pix de 50'), null);
  assert.equal(isStatusQueryMessage('Problema no pix de 50'), true);
  assert.equal(parseBrlAmountFromText('Problema no pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Sem problema, pix de 50'), 50);
  assert.equal(isStatusQueryMessage('Meu pix de 50 ainda está em processamento no banco'), true);
  assert.equal(parseBrlAmountFromText('Meu pix de 50 ainda está em processamento no banco'), null);
  assert.equal(isStatusQueryMessage('O pix de 50 ficou pendente no banco'), true);
  assert.equal(parseBrlAmountFromText('O pix de 50 ficou pendente no banco'), null);
  assert.equal(isStatusQueryMessage('Estão retendo meu pix de 50 no banco'), true);
  assert.equal(parseBrlAmountFromText('Estão retendo meu pix de 50 no banco'), null);
  assert.equal(parseBrlAmountFromText('Houve retenção no meu pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Caiu em duplicidade o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Saiu em duplicidade o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Foi pago em duplicidade o pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Me cobraram 50 reais duas vezes no pix'), null);
  assert.equal(isStatusQueryMessage('Saiu duas vezes 50 reais da minha conta no pix'), true);
  assert.equal(parseBrlAmountFromText('Saiu duas vezes 50 reais da minha conta no pix'), null);

  // Achado 4: "quanto" posposto, desconto com plural e conversão/compra inversa de cripto/moeda
  assert.equal(parseBrlAmountFromText('Custa quanto no pix? 50?'), null);
  assert.equal(parseBrlAmountFromText('Fica quanto no pix? 80?'), null);
  assert.equal(parseBrlAmountFromText('Tá quanto no pix? 50?'), null);
  assert.equal(parseBrlAmountFromText('Sai quanto no pix? 50?'), null);
  assert.equal(parseBrlAmountFromText('Dá quanto tudo no pix? 150?'), null);
  assert.equal(parseBrlAmountFromText('Fica quanto com desconto os 100 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Comprar BTC com 100 reais no pix'), null);
  assert.equal(parseBrlAmountFromText('Quero comprar USDT com R$ 500 no pix'), null);
  assert.equal(parseBrlAmountFromText('100 reais dá quantos USDT no pix?'), null);

  // Achado 5: menu 1 / 2 com vírgula ("2, 80 reais") e artigo + preposição ("Quero a 2 de 80", "Gera a 2 de R$ 80") sem capturar "Quero 2 de 50"
  assert.deepEqual(parseActiveOrderMenuReply('2, 80 reais'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 80,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2, 150,00'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 150,
  });
  assert.deepEqual(parseActiveOrderMenuReply('1, essa mesma'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Quero a 2 de 80'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 80,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Gera a 2 de R$ 80'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 80,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Vou na 2 de 100'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 100,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Quero 2 de 50'), {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: null,
  });
});

test('Busca #29: filtro keyword_only pós-pedido sem invadir conversas pessoais, concluí/finalizei e "vê se caiu", perguntas coloquiais/pechincha, gerúndios/posse negativa/câmbio e CEP/conta/DV/tokens inválidos', async () => {
  // Achado 1: filtro keyword_only + preservação de IDLE em consultas de status pós-erro/expiração
  const { repository, engine } = createPrivacyTestSetup();
  try {
    const baileys = new BaileysDirectManager(repository, 'data/wa_auth_test_29', {
      filterMode: 'keyword_only',
    });
    const friendPhone = '5511966661111';

    await engine.handleIncomingMessage({ phone: friendPhone, text: 'Me manda um Pix de 50' });
    const ord = repository.findMostRecentOrderByPhone(friendPhone);
    assert.ok(ord);

    // Liquida o pedido -> sessão fica IDLE
    await engine.handleSettlementWebhook({
      provider: 'mock',
      externalId: ord.externalId,
      newStatus: 'SETTLED_CRYPTO',
      rawEventName: 'MOCK_PAID',
    });
    assert.equal(repository.getSession(friendPhone).stage, 'IDLE');

    // Mensagens pessoais nas 24h seguintes NUNCA passam pelo filtro keyword_only!
    for (const personalMsg of [
      'Você já chegou em casa?',
      'Deu tudo certo na viagem?',
      'Meu celular travou',
      'Ele cancelou o jantar',
      'Tive um problema hoje',
      'Me ajuda aqui',
      'Paguei 50 no mercado hoje',
      'Parar',
      'Menu',
    ]) {
      assert.equal(
        baileys.shouldForwardIncomingMessage(friendPhone, personalMsg),
        false,
        `Mensagem pessoal "${personalMsg}" deveria ser bloqueada em keyword_only`
      );
      assert.equal(isPostOrderFollowUpMessage(personalMsg), false);
    }
    assert.equal(isStatusQueryMessage('Você já chegou em casa?'), false);
    assert.equal(isStatusQueryMessage('Deu tudo certo na viagem?'), false);
    assert.equal(isStatusQueryMessage('Meu celular travou'), false);
    assert.equal(isStatusQueryMessage('Ele cancelou o jantar'), false);
    assert.equal(isStatusQueryMessage('Tive um problema hoje'), false);
    assert.equal(isHelpCommand('Me ajuda aqui'), false);
    assert.equal(isPaymentConfirmationMessage('Paguei 50 no mercado hoje'), false);
    assert.equal(parseBrlAmountFromText('Paguei 50 no mercado hoje'), null);

    // Já consultas/confirmações financeiras reais passam normalmente após pedido liquidado!
    for (const genuineFollowUp of [
      'Já paguei!',
      'Tá pago',
      'Status',
      'Já caiu?',
      'Descontou 50 reais da minha conta',
      'Foi estornado!',
    ]) {
      assert.equal(baileys.shouldForwardIncomingMessage(friendPhone, genuineFollowUp), true);
    }

    // Se o cliente abrir novo pedido e encerrar com "sair" (CANCELLED + IDLE), nem follow-ups sem "pix" acordam o robô!
    await engine.handleIncomingMessage({ phone: friendPhone, text: 'Pix de 70' });
    await engine.handleIncomingMessage({ phone: friendPhone, text: 'sair' });
    assert.equal(repository.getSession(friendPhone).stage, 'IDLE');
    assert.equal(repository.findMostRecentOrderByPhone(friendPhone)?.status, 'CANCELLED');
    assert.equal(baileys.shouldForwardIncomingMessage(friendPhone, 'Status'), false);
    assert.equal(baileys.shouldForwardIncomingMessage(friendPhone, 'Status do meu pix'), true);

    // E quando o usuário em IDLE envia relato de erro/status com a palavra "pix", a sessão permanece IDLE (não reabre janela de 2h!)
    await engine.handleIncomingMessage({
      phone: friendPhone,
      text: 'O banco cancelou meu pix de 70',
    });
    assert.equal(repository.getSession(friendPhone).stage, 'IDLE');
    assert.equal(baileys.shouldForwardIncomingMessage(friendPhone, 'São 50'), false);

    // Achado 2: concluí/finalizei e consultas de compensação sem "?" nunca geram cobrança duplicada!
    const ordersBeforeDupCheck = repository.listRecentOrders().length;
    for (const postPaidMsg of [
      'Concluí o pix de 50',
      'Conclui o pix de 50',
      'Já concluí o pagamento de R$ 50,00',
      'Finalizei o pix de 50!',
      'Acabei de concluir o pix de 50',
      'Consegui finalizar o pagamento de R$ 50',
      'Vê se o pix de 50 caiu',
      'Confere se entrou os 50 no pix',
      'Olha aí se caiu R$ 50 no pix',
      'Vê se recebeu os 50 do pix',
      'O pix de 50 caiu aí',
      'O pagamento de R$ 50 entrou aí',
    ]) {
      await engine.handleIncomingMessage({ phone: friendPhone, text: postPaidMsg });
    }
    assert.equal(repository.listRecentOrders().length, ordersBeforeDupCheck);
  } finally {
    repository.close();
  }

  assert.equal(isPaymentConfirmationMessage('Concluí o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Já concluí o pagamento de R$ 50,00'), true);
  assert.equal(isPaymentConfirmationMessage('Finalizei o pix de 50!'), true);
  assert.equal(isPaymentConfirmationMessage('Acabei de concluir o pix de 50'), true);
  assert.equal(isPaymentConfirmationMessage('Não concluí o pix de 50 ainda'), false);
  assert.equal(parseBrlAmountFromText('Não concluí o pix de 50 ainda'), null);
  assert.equal(isStatusQueryMessage('Vê se o pix de 50 caiu'), true);
  assert.equal(isStatusQueryMessage('Confere se entrou os 50 no pix'), true);
  assert.equal(isStatusQueryMessage('Olha aí se caiu R$ 50 no pix'), true);
  assert.equal(isStatusQueryMessage('Vê se recebeu os 50 do pix'), true);
  assert.equal(isStatusQueryMessage('O pix de 50 caiu aí'), true);
  assert.equal(isStatusQueryMessage('O pagamento de R$ 50 entrou aí'), true);

  // Achado 3: perguntas coloquiais ("quanto que", "qual que", "ganho desconto", "acréscimo", objeto antes de "por") e pechinchas condicionais
  assert.equal(parseBrlAmountFromText('Quanto que tá o corte no pix? 50?'), null);
  assert.equal(parseBrlAmountFromText('Quanto que fica com entrega no pix? 80?'), null);
  assert.equal(parseBrlAmountFromText('Qual que é o preço no pix? 50'), null);
  assert.equal(parseBrlAmountFromText('Ganho desconto pagando 100 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Tenho desconto no pix de 100?'), null);
  assert.equal(parseBrlAmountFromText('Tem acréscimo no pix de 100?'), null);
  assert.equal(parseBrlAmountFromText('Consegue fazer o serviço por 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Faz esse produto por 50 no pix?'), null);
  assert.equal(parseBrlAmountFromText('Se fizer por 50 eu pago no pix'), null);
  assert.equal(parseBrlAmountFromText('Se for 50 eu faço o pix'), null);
  assert.equal(parseBrlAmountFromText('Pode fazer um pix de 50?'), 50);
  assert.equal(parseBrlAmountFromText('Se puder, me manda um pix de 50'), 50);

  // Achado 4: gerúndios bancários, negação de posse ("não tenho", "estou sem") e câmbio/cripto em oração separada
  for (const gerundHold of [
    'O banco está segurando meu pix de 50',
    'O banco está analisando meu pix de 50',
    'O banco está bloqueando meu pix de 50',
    'O banco está recusando o pix de 50',
    'Está rejeitando o pix de 50',
    'Está negando meu pix de 50',
  ]) {
    assert.equal(isStatusQueryMessage(gerundHold), true);
    assert.equal(parseBrlAmountFromText(gerundHold), null);
  }
  assert.equal(parseBrlAmountFromText('Não tenho 50 reais pro pix agora'), null);
  assert.equal(parseBrlAmountFromText('Não tenho os 50 reais do pix'), null);
  assert.equal(parseBrlAmountFromText('Estou sem 50 reais pro pix agora'), null);
  assert.equal(parseBrlAmountFromText('Fiquei sem dinheiro pro pix de 50'), null);
  assert.equal(parseBrlAmountFromText('Tô sem dinheiro em espécie, manda um pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Comprar dólar no pix, 100 reais'), null);
  assert.equal(parseBrlAmountFromText('Quero comprar USDT no pix, tenho 100 reais'), null);
  assert.equal(parseBrlAmountFromText('Tenho 100 reais no pix, quero BTC'), null);
  assert.equal(parseBrlAmountFromText('Óculos de sol, manda pix de 100'), 100);

  // Achado 5: CEP/conta/agência/CPF com espaço antes do sufixo/DV e não-descarte de `0` ou `> 10_000_000`
  assert.equal(parseBrlAmountFromText('cep 01310 100 quero fazer pix'), null);
  assert.equal(parseBrlAmountFromText('cep 01310 100, manda pix de 80'), 80);
  assert.equal(parseBrlAmountFromText('conta 12345 6 quero pix'), null);
  assert.equal(parseBrlAmountFromText('ag 1234 cc 56789 5 quero pix'), null);
  assert.equal(parseBrlAmountFromText('ag 1234 cc 56789 5, manda pix de 80'), 80);
  assert.equal(parseBrlAmountFromText('meu cpf é 123.456.789 50 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('meu cpf é 123.456.789 50, manda pix de 80'), 80);
  assert.equal(parseBrlAmountFromText('meu cpf é 123456789 50 quero fazer um pix'), null);
  assert.equal(parseBrlAmountFromText('pix de 0 ou 50'), null);
  assert.equal(parseBrlAmountFromText('pix de 20.000.000 ou 50'), null);
  assert.equal(parseBrlAmountFromText('pix de 100000000 ou 50'), null);
});

test('Busca #30: numerais por extenso com pontuação final, pronomes proclíticos (te/lhe), duplicidade/engano, dúvidas de parcelamento/cartão/diminutivos e contraste no menu 1 / 2', async () => {
  // Achado 1: pontuação de frase (".", "...", " - ") NUNCA trunca nem bloqueia numerais por extenso!
  assert.equal(parseBrlAmountFromText('Me manda um pix de dois mil e quinhentos.'), 2500);
  assert.equal(parseBrlAmountFromText('Pix de dois mil, quinhentos.'), 2500);
  assert.equal(parseBrlAmountFromText('Oi. Dois mil e quinhentos reais no pix'), 2500);
  assert.equal(parseBrlAmountFromText('Pix de vinte e cinco e cinquenta.'), 25.5);
  assert.equal(parseBrlAmountFromText('Me manda um pix de cinquenta.'), 50);
  assert.equal(parseBrlAmountFromText('Pix de cem.'), 100);
  assert.equal(parseBrlAmountFromText('Pix de cento e cinquenta.'), 150);
  assert.equal(parseBrlAmountFromText('Pix de cinquenta...'), 50);
  assert.equal(parseBrlAmountFromText('Pix de cinquenta. Obrigado!'), 50);
  assert.equal(parseBrlAmountFromText('Pix - cinquenta'), 50);
  assert.equal(parseBrlAmountFromText('segue arquivo cinquenta.pdf quero pix'), null);

  assert.deepEqual(parseActiveOrderMenuReply('2 - cinquenta.'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 50,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Quero a 2, manda de cinquenta.'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 50,
  });
  assert.equal(hasUnparsedDigitsInMenuReply('2 - cinquenta.'), true);

  // Achado 2: pronomes proclíticos ("te", "lhe") em confirmações pós-pagamento, tentativas falhas, negações e follow-up keyword_only
  for (const paidWithTe of [
    'Acabei de te mandar 50 no pix',
    'Acabei de te pagar 50 no pix',
    'Acabei de te enviar o pix de 50',
    'Consegui te mandar o pix de 50',
    'Já te mandei 50 no pix',
    'Te enviei o pix de 50',
  ]) {
    assert.equal(isPaymentConfirmationMessage(paidWithTe), true, paidWithTe);
  }

  for (const failedAttemptWithTe of [
    'Tentei te mandar o pix de 50',
    'Tentei te pagar 50 no pix',
    'Tentei te fazer um pix de 50',
    'Não tô conseguindo te mandar 50 no pix',
  ]) {
    assert.equal(isStatusQueryMessage(failedAttemptWithTe), true, failedAttemptWithTe);
    assert.equal(parseBrlAmountFromText(failedAttemptWithTe), null, failedAttemptWithTe);
  }

  for (const negatedWithTe of [
    'Ainda não te paguei os 50 do pix',
    'Não te mandei o pix de 50 ainda',
    'Eu não te paguei os 50 do pix?',
    'Não te mandei 50 no pix?',
    'Quase te mandei 50 no pix',
  ]) {
    assert.equal(isPaymentConfirmationMessage(negatedWithTe), false, negatedWithTe);
    assert.equal(parseBrlAmountFromText(negatedWithTe), null, negatedWithTe);
  }

  for (const shortFollowUp of [
    'Te paguei!',
    'Já te paguei!',
    'Acabei de pagar!',
    'Acabei de transferir!',
    'Compensou aí?',
    'Já entrou aí?',
    'Caiu na conta?',
  ]) {
    assert.equal(isPostOrderFollowUpMessage(shortFollowUp), true, shortFollowUp);
  }

  // Achado 3: relatos de pagamento duplicado com "fiz"/"efetuei"/"pagou" e pagamento errado/por engano
  for (const dupOrMistake of [
    'Fiz 2 vezes o pix de 50',
    'Fiz 2x o pix de 50',
    'Efetuei 2 vezes o pix de 50',
    'Pagou 2 vezes o pix de 50',
    'Fiz o pix de 50 duas vezes',
    'Fiz o pix de 50 errado, como faço?',
    'Enviei 50 no pix por engano, o que faço?',
  ]) {
    assert.equal(isStatusQueryMessage(dupOrMistake), true, dupOrMistake);
    assert.equal(parseBrlAmountFromText(dupOrMistake), null, dupOrMistake);
  }

  // Achado 4: perguntas no plural/pretérito ("São 50?", "Ficou 80?", "Deu 120?"), parcelamento/cartão/boleto e diminutivos de tempo
  for (const inquiryOrTime of [
    'São 50 reais no pix?',
    'São 50 reais mesmo no pix?',
    'É mesmo 50 no pix?',
    'Ficou 80 reais no pix?',
    'Deu 120 reais no pix?',
    'Total deu 150 no pix?',
    'Dá pra parcelar os 500 no pix?',
    'Parcela 300 no pix?',
    'Aceita pix parcelado de 500?',
    'Posso passar 100 no cartão de crédito ou pix?',
    '50 no débito ou no pix?',
    'Tem boleto de 100 ou só pix?',
    'Em 5 minutinhos mando o pix',
    'Daqui a 2 horinhas faço o pix',
    'Mando o pix em 10 segundinhos',
    'Em um minutinho mando o pix',
  ]) {
    assert.equal(parseBrlAmountFromText(inquiryOrTime), null, inquiryOrTime);
  }
  assert.equal(parseBrlAmountFromText('São 50 reais no pix'), 50);
  assert.equal(parseBrlAmountFromText('Ficou 80 reais no pix'), 80);

  // Achado 5: bloqueio de conversas pessoais em keyword_only (celular/cartão/Amazon/ingresso/arquivos/pedido/reunião/orçamento) + contraste no menu 1 / 2
  for (const personalChat of [
    'Tô sem saldo no celular',
    'Estourou o limite do cartão',
    'Fizeram o estorno da Amazon',
    'Pedi reembolso do ingresso',
    'Fiz a transferência dos arquivos',
    'Já chegou o pedido?',
    'Confirmou a reunião?',
    'Aprovou o orçamento?',
  ]) {
    assert.equal(isPostOrderFollowUpMessage(personalChat), false, personalChat);
  }
  assert.equal(isStatusQueryMessage('Já chegou o pedido?'), false);
  assert.equal(isStatusQueryMessage('Confirmou a reunião?'), false);
  assert.equal(isStatusQueryMessage('Aprovou o orçamento?'), false);
  assert.equal(isPaymentConfirmationMessage('Fiz a transferência dos arquivos'), false);

  assert.deepEqual(parseActiveOrderMenuReply('Não quero a 2, manda a 1'), {
    choice: 'resend',
    explicitOptionDigit: '1',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('Não quero a 1, quero a 2'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.equal(hasUnparsedDigitsInMenuReply('Não quero a 1, quero a 2'), false);
  assert.deepEqual(parseActiveOrderMenuReply('Não quero a 1, faz a 2 de 120'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: 120,
  });

  // Integração E2E no ConversationEngine: "2 - cinquenta." sobrescreve valor pendente de 80 -> 50, e "Não quero a 1, quero a 2" preserva 80!
  const { repository, engine } = createPrivacyTestSetup();
  try {
    const p1 = '5511933331111';
    await engine.handleIncomingMessage({ phone: p1, text: 'Pix de 60' });
    await engine.handleIncomingMessage({ phone: p1, text: 'Pix de 80' });
    await engine.handleIncomingMessage({ phone: p1, text: '2 - cinquenta.' });
    assert.equal(repository.findMostRecentOrderByPhone(p1)?.amountBrl, 50);

    const p2 = '5511933332222';
    await engine.handleIncomingMessage({ phone: p2, text: 'Pix de 60' });
    await engine.handleIncomingMessage({ phone: p2, text: 'Pix de 80' });
    await engine.handleIncomingMessage({ phone: p2, text: 'Não quero a 1, quero a 2' });
    assert.equal(repository.findMostRecentOrderByPhone(p2)?.amountBrl, 80);
  } finally {
    repository.close();
  }
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

  // Corrida Busca #22: cobrança venceu há 2s no relógio (ANTES do ExpirationWatcher rodar) e menu abriu há 10 min:
  // responder "2" DEVE gerar R$ 90 (e nunca R$ 2!), e responder "1" em outra janela vencida avisa expiração (e nunca cobra R$ 1!)
  const phoneClockRace = '5511977771111';
  const nowRaceMs = Date.now();
  repository.createOrder({
    id: 'ord_clock_race_1',
    externalId: 'ext_clock_race_1',
    provider: 'mock',
    providerChargeId: 'mock_clock_race_1',
    customerPhone: phoneClockRace,
    amountBrl: 50,
    estimatedCryptoAmount: 50,
    cryptoAsset: 'DEPIX',
    cryptoNetwork: 'LIQUID',
    walletAddress: 'Carteira Liquid',
    pixCopyPaste: '000201_clock_race_1',
    status: 'PENDING',
    warningSent: true,
    createdAt: new Date(nowRaceMs - 15 * 60_000 - 2_000).toISOString(),
    expiresAt: new Date(nowRaceMs - 2_000).toISOString(),
  });
  repository.saveSession(
    {
      phone: phoneClockRace,
      stage: 'AWAITING_ACTIVE_ORDER_DECISION',
      pendingNewAmountBrl: 90,
      updatedAt: new Date(nowRaceMs - 10 * 60_000).toISOString(),
    },
    true
  );
  await engine.handleIncomingMessage({ phone: phoneClockRace, text: '2' });
  assert.equal(repository.findMostRecentOrderByPhone(phoneClockRace)?.amountBrl, 90);

  const phoneClockRaceOpt1 = '5511977772222';
  repository.createOrder({
    id: 'ord_clock_race_2',
    externalId: 'ext_clock_race_2',
    provider: 'mock',
    providerChargeId: 'mock_clock_race_2',
    customerPhone: phoneClockRaceOpt1,
    amountBrl: 50,
    estimatedCryptoAmount: 50,
    cryptoAsset: 'DEPIX',
    cryptoNetwork: 'LIQUID',
    walletAddress: 'Carteira Liquid',
    pixCopyPaste: '000201_clock_race_2',
    status: 'PENDING',
    warningSent: true,
    createdAt: new Date(nowRaceMs - 15 * 60_000 - 2_000).toISOString(),
    expiresAt: new Date(nowRaceMs - 2_000).toISOString(),
  });
  repository.saveSession(
    {
      phone: phoneClockRaceOpt1,
      stage: 'AWAITING_ACTIVE_ORDER_DECISION',
      pendingNewAmountBrl: 90,
      updatedAt: new Date(nowRaceMs - 10 * 60_000).toISOString(),
    },
    true
  );
  await engine.handleIncomingMessage({ phone: phoneClockRaceOpt1, text: '1' });
  assert.equal(repository.findMostRecentOrderByPhone(phoneClockRaceOpt1)?.id, 'ord_clock_race_2');
  assert.equal(repository.getSession(phoneClockRaceOpt1).stage, 'AWAITING_AMOUNT');

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

test('11. Busca #31: emojis WhatsApp, menu 1/2 ("É a 2", "2 🙏"), "e meio", "50pila", endereços compostos e falsos positivos', async () => {
  // Bug 1: Menu 1 / 2 com emojis, verbos de ligação ("É a 2", "A opção é a 2", "Não é a 1, é a 2") e infinitivo ("Pode mandar a atual")
  const menuResendCases: Array<[string, '1' | null]> = [
    ['1 👍', '1'],
    ['1✅', '1'],
    ['1️⃣ 🙏', '1'],
    ['É a 1', '1'],
    ['Seria a 1', '1'],
    ['A opção é a 1', '1'],
    ['Não é a 2, é a 1', '1'],
    ['Pode mandar a atual', null],
    ['Mandar a atual', null],
    ['Pode enviar o pix atual', null],
  ];
  for (const [msg, expectedDigit] of menuResendCases) {
    assert.deepEqual(
      parseActiveOrderMenuReply(msg),
      { choice: 'resend', explicitOptionDigit: expectedDigit, inlineNewAmountBrl: null },
      `Falha menu resend em: ${msg}`
    );
    assert.equal(hasUnparsedDigitsInMenuReply(msg), false, `Dígito extra falso em: ${msg}`);
  }

  const menuNewCases: Array<[string, '2' | null, number | null]> = [
    ['2 🙏', '2', null],
    ['2 👍', '2', null],
    ['2✅', '2', null],
    ['*2*✅', '2', null],
    ['2️⃣ 🙏', '2', null],
    ['É a 2', '2', null],
    ['É 2', '2', null],
    ['Seria a 2', '2', null],
    ['A opção é a 2', '2', null],
    ['Minha escolha é a 2', '2', null],
    ['Não é a 1, é a 2', '2', null],
    ['Não é 1, é 2', '2', null],
  ];
  for (const [msg, expectedDigit, expectedAmt] of menuNewCases) {
    assert.deepEqual(
      parseActiveOrderMenuReply(msg),
      { choice: 'new', explicitOptionDigit: expectedDigit, inlineNewAmountBrl: expectedAmt },
      `Falha menu new em: ${msg}`
    );
    assert.equal(hasUnparsedDigitsInMenuReply(msg), false, `Dígito extra falso em: ${msg}`);
  }

  // Bug 2: Comandos e acompanhamento pós-pedido com emojis e valores sem repetir "pix"
  assert.equal(isExitCommand('sair 🙏'), true);
  assert.equal(isCancelCommand('cancelar 👍'), true);
  assert.equal(isHelpCommand('ajuda 🙏'), true);
  assert.equal(isStatusQueryMessage('status 🙏'), true);
  assert.equal(isStatusQueryMessage('Já caiu? 🙏'), true);
  assert.equal(isPaymentConfirmationMessage('pago ✅'), true);
  assert.equal(isPaymentConfirmationMessage('Já paguei ✅'), true);

  const validFollowUps = [
    'Já paguei ✅',
    'Já paguei! 🙏',
    'Tá pago ✅',
    'pago ✅',
    'status 🙏',
    'Já tá pago!',
    'Tá pago os 50!',
    'Já foi pago os 50',
    'Enviei os 50 reais',
    'Mandei os 50 reais aí',
    'Transferi os 50 reais agora',
    'Já caiu os 50?',
    'Caiu aí os 50 reais?',
    'Entrou aí os 50?',
    'Confirmou aí os 50?',
  ];
  for (const msg of validFollowUps) {
    assert.equal(isPostOrderFollowUpMessage(msg), true, `Deveria aceitar follow-up: ${msg}`);
  }

  const invalidFollowUps = [
    'Mandei 50 mensagens',
    'Enviei 50 fotos',
    'Paguei 50 no mercado hoje',
    'Já chegou o pedido?',
    'Confirmou a reunião?',
    '🙏🙏',
  ];
  for (const msg of invalidFollowUps) {
    assert.equal(isPostOrderFollowUpMessage(msg), false, `Não deveria aceitar follow-up: ${msg}`);
  }

  // Bug 3 & Bug 4: "e meio", "50pila", emojis colados ao valor e endereços compostos
  const validAmounts: Array<[string, number]> = [
    ['pix de dez reais e meio', 10.5],
    ['pix de 50 reais e meio', 50.5],
    ['pix de 15 e meio', 15.5],
    ['pix de um e meio', 1.5],
    ['pix de vinte contos e meio', 20.5],
    ['pix de uma pila e meia', 1.5],
    ['pix de 50pila', 50],
    ['Pix de 50🚀', 50],
    ['50,00✅', 50],
    ['Quadra 10 Lote 5, manda pix de 80', 80],
    ['Bloco 2 Sala 204, manda pix de 80', 80],
    ['Andar 3 Sala 12, manda pix de 80', 80],
    ['Av. Brasil 500 Sala 10, manda pix de 80', 80],
    ['Torre 1 Apto 502, manda pix de 80', 80],
  ];
  for (const [msg, expected] of validAmounts) {
    assert.equal(parseBrlAmountFromText(msg), expected, `Valor esperado ${expected} em: ${msg}`);
  }

  // Bug 5: Horários coloquiais, pechincha/preço, relatos de Pix expirado e transferências saintes
  const blockedFalsePositives = [
    '10 e meia mando o pix',
    'Cinco e meia faço o pix',
    'À 1 mando o pix',
    'À 1 e meia mando o pix',
    '15 pras 4 mando o pix',
    '10 para as 5 mando o pix',
    'Três e vinte faço o pix',
    'À vista no pix sai por quanto? 80?',
    'Faz 80 no pix?',
    'No pix faz 80?',
    'Fecha 80 no pix?',
    'Deixa 80 no pix?',
    'Dá pra fazer 80 no pix?',
    'Consegue fazer 80 no pix?',
    'Se eu pagar à vista no pix faz 80?',
    'Pagando à vista no pix cai pra 80?',
    'O pix de 50 expirou',
    'Venceu o pix de 50',
    'Expirou a cobrança de 50',
    'Minha cobrança de 50 está vencida',
    'Manda 50 na minha chave pix',
    'Envia 50 pra minha chave pix',
    'Faz um pix de 50 pra minha conta',
    'Transfere 50 pro meu pix',
    'Deposita 50 na minha conta bancária',
    'Você me deve 50 no pix',
    '2 e meio kg',
    '2 quilos e meio por 50',
  ];
  for (const msg of blockedFalsePositives) {
    assert.equal(parseBrlAmountFromText(msg), null, `Deveria bloquear falso positivo: ${msg}`);
  }

  for (const expMsg of [
    'O pix de 50 expirou',
    'Venceu o pix de 50',
    'Expirou a cobrança de 50',
    'Minha cobrança de 50 está vencida',
  ]) {
    assert.equal(isStatusQueryMessage(expMsg), true, `Deveria ser consulta de status: ${expMsg}`);
  }

  // Fluxo E2E no ConversationEngine + BaileysDirectManager (garante que "2 🙏" / "É a 2" gera R$ 80,00 e NUNCA R$ 2,00!)
  const { repository, engine } = createPrivacyTestSetup();
  try {
    const baileys = new BaileysDirectManager(repository, 'data/test_wa_auth_unused', {
      filterMode: 'keyword_only',
    });
    const phone = '5511944445555';

    await engine.handleIncomingMessage({ phone, text: 'Pix de 60' });
    assert.equal(repository.findActivePendingOrderByPhone(phone)?.amountBrl, 60);

    await engine.handleIncomingMessage({ phone, text: 'Pix de 80' });
    assert.equal(repository.getSession(phone).stage, 'AWAITING_ACTIVE_ORDER_DECISION');
    assert.equal(repository.getSession(phone).pendingNewAmountBrl, 80);

    await engine.handleIncomingMessage({ phone, text: '2 🙏' });
    assert.equal(repository.findActivePendingOrderByPhone(phone)?.amountBrl, 80);

    await engine.handleIncomingMessage({ phone, text: 'Pix de 95' });
    await engine.handleIncomingMessage({ phone, text: 'É a 2' });
    const settledTarget = repository.findActivePendingOrderByPhone(phone);
    assert.equal(settledTarget?.amountBrl, 95);

    // Após liquidar a cobrança, sessão fica IDLE e keyword_only aceita "Já paguei ✅" / "Já caiu os 95?" sem invadir "Mandei 50 mensagens"
    repository.applySettlementUpdate({
      orderId: settledTarget!.id,
      newStatus: 'SETTLED_CRYPTO',
    });
    repository.saveSession({ phone, stage: 'IDLE', updatedAt: new Date().toISOString() });
    assert.equal(baileys.shouldForwardIncomingMessage(phone, 'Já paguei ✅'), true);
    assert.equal(baileys.shouldForwardIncomingMessage(phone, 'Já caiu os 95?'), true);
    assert.equal(baileys.shouldForwardIncomingMessage(phone, 'Mandei 50 mensagens'), false);
  } finally {
    repository.close();
  }
});

test('12. Busca #32: fronteiras Unicode (milímetros/°C), invisíveis ZWSP/LRM, menu ("Sim, a 2", "2 obg"), "voltou"/dando inválido, horários ("dez pra uma"), "mil" livre e "Pronto, já paguei!"', async () => {
  // Achado 1: Unidades por extenso / °C sem corromper "milímetros" em "mil\b"
  assert.equal(parseBrlAmountFromText('Chapa de 10 centímetros, aceita pix?'), null);
  assert.equal(parseBrlAmountFromText('Fita de 20 milimetros no pix'), null);
  assert.equal(parseBrlAmountFromText('Cabo de 6 milímetros no pix'), null);
  assert.equal(parseBrlAmountFromText('Remédio de 500 miligramas no pix'), null);
  assert.equal(parseBrlAmountFromText('Seringa de 10 mililitros no pix'), null);
  assert.equal(parseBrlAmountFromText('Forno 180 °C no pix'), null);
  assert.equal(parseBrlAmountFromText('Cabo de 10 centímetros, manda um pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Cabo de 6 milímetros, manda um pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Cabo de 6 milimetros, manda um pix de 50'), 50);

  // Achado 2: Caracteres invisíveis do WhatsApp (ZWSP, LRM, RLM, BiDi, BOM, soft hyphen)
  assert.equal(isExitCommand('\u200Bsair'), true);
  assert.equal(isCancelCommand('\u200Ecancelar'), true);
  assert.equal(isStatusQueryMessage('\u200Bstatus'), true);
  assert.equal(isPaymentConfirmationMessage('\u200Bpago'), true);
  assert.deepEqual(parseActiveOrderMenuReply('\u200E2'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.deepEqual(parseActiveOrderMenuReply('2\u200B'), {
    choice: 'new',
    explicitOptionDigit: '2',
    inlineNewAmountBrl: null,
  });
  assert.equal(hasUnparsedDigitsInMenuReply('\u200E2'), false);

  // Achado 3: Confirmações e cortesias coloquiais no menu 1 / 2
  for (const msg of [
    'Sim, a 2',
    'Ok, a 2',
    'Beleza, a 2',
    'Por favor, a 2',
    'Bora na 2',
    'Vamos de 2',
    'Pela 2',
    '2 obg',
    '2 vlw',
    'Oi, bom dia! É a 2',
  ]) {
    assert.deepEqual(
      parseActiveOrderMenuReply(msg),
      { choice: 'new', explicitOptionDigit: '2', inlineNewAmountBrl: null },
      `Menu opção 2 falhou em: ${msg}`
    );
    assert.equal(hasUnparsedDigitsInMenuReply(msg), false, `Dígito extra falso em: ${msg}`);
  }
  for (const msg of ['Sim, a 1', 'Ok, 1', '1 obg', '1 vlw', 'Pela 1']) {
    assert.deepEqual(
      parseActiveOrderMenuReply(msg),
      { choice: 'resend', explicitOptionDigit: '1', inlineNewAmountBrl: null },
      `Menu opção 1 falhou em: ${msg}`
    );
  }

  // Achado 4: Estornos curtos ("voltou"), erro aspectual ("dando inválido") e pagamento a maior/repetido
  for (const msg of [
    'Meu pix de 50 voltou',
    'O pix de 50 voltou',
    'Os 50 reais voltaram',
    'O pagamento de 50 retornou',
    'O código de 50 está dando inválido',
    'O link de 50 aparece inválido',
    'Mandei 50 a mais no pix sem querer',
    'Paguei 50 a mais no pix',
  ]) {
    assert.equal(isStatusQueryMessage(msg), true, `Status deveria ser true em: ${msg}`);
    assert.equal(parseBrlAmountFromText(msg), null, `Não deveria cobrar em: ${msg}`);
  }
  assert.equal(parseBrlAmountFromText('Voltei agora, manda pix de 50'), 50);

  // Achado 5: Horários ("vinte para as três", "dez pra uma"), troco/pechincha/misto e chave/empréstimo
  for (const msg of [
    'vinte para as três faço o pix',
    'dez pra uma mando o pix',
    '15 pra meia-noite mando o pix',
    'Tem troco pra 100 no pix?',
    'Fecha em 80 no pix?',
    'Dá pra fechar em 80 no pix?',
    'Consegue abaixar pra 80 no pix?',
    'Consegue tirar 10 reais no pix?',
    'Quero pagar metade no cartão e 50 no pix',
    'Passo no cartão e 50 no pix',
    'Me faz um pix de 50, minha chave é 11988887777',
    'Manda 50 no pix, minha chave é joao@gmail.com',
    'Me empresta 50 no pix?',
  ]) {
    assert.equal(parseBrlAmountFromText(msg), null, `Falso positivo em: ${msg}`);
  }
  assert.equal(parseBrlAmountFromText('Meu cartão não passou, manda um pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Manda um pix de 50 pra uma amiga'), 50);

  // Achado 6: "mil" livre e milhares compostos com centavos por extenso
  assert.equal(parseBrlAmountFromText('Bom dia mil reais no pix'), 1000);
  assert.equal(parseBrlAmountFromText('Manda aqui mil reais no pix'), 1000);
  assert.equal(parseBrlAmountFromText('Gera lá mil reais no pix'), 1000);
  assert.equal(
    parseBrlAmountFromText('pix de dois mil e quinhentos e cinquenta centavos'),
    2500.5
  );
  assert.equal(parseBrlAmountFromText('Hoje o dia tá a mil, manda pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Mil desculpas pela demora, manda pix de 50'), 50);

  // Achado 7: Prefixos conversacionais ("Pronto, ...") e "já" posposto em isPostOrderFollowUpMessage
  for (const msg of [
    'Pronto, já paguei!',
    'Pronto, tá pago!',
    'Pronto, paguei os 50!',
    'Tá pago já!',
    'Foi pago já!',
    'Oi, já caiu?',
  ]) {
    assert.equal(isPostOrderFollowUpMessage(msg), true, `Follow-up deveria aceitar: ${msg}`);
  }
  assert.equal(isPostOrderFollowUpMessage('Pronto, mandei 50 mensagens'), false);
});

test('13. Busca #33: menu ("01"/"02"/"Opc 2"/"Quero a atual"), sufixo "k", novos pedidos por vírgula ("manda de 100"), "Transferi!", cobrança a maior/bloqueio/conta errada, "Aceita 80?", saudações em comandos e "hum mil"', () => {
  // Achado 1: Menu 1 / 2 com zero à esquerda, abreviações e "atual"
  for (const msg of ['01', 'Opção 01', 'Opc 1', 'Nº 1', 'Num 1']) {
    assert.deepEqual(
      parseActiveOrderMenuReply(msg),
      { choice: 'resend', explicitOptionDigit: '1', inlineNewAmountBrl: null },
      `Falha menu 01 em: ${msg}`
    );
    assert.equal(hasUnparsedDigitsInMenuReply(msg), false);
  }
  for (const msg of [
    'Quero a atual',
    'Pode ser a atual',
    'Fico com a atual',
    'Prefiro a atual',
    'A atual',
    'Essa atual',
  ]) {
    assert.deepEqual(
      parseActiveOrderMenuReply(msg),
      { choice: 'resend', explicitOptionDigit: null, inlineNewAmountBrl: null },
      `Falha menu atual em: ${msg}`
    );
  }
  for (const [msg, amt] of [
    ['02', null],
    ['Opc 2', null],
    ['Opção 02', null],
    ['Nº 2', null],
    ['Num 2', null],
    ['02 - gerar 120', 120],
  ] as Array<[string, number | null]>) {
    assert.deepEqual(
      parseActiveOrderMenuReply(msg),
      { choice: 'new', explicitOptionDigit: '2', inlineNewAmountBrl: amt },
      `Falha menu 02 em: ${msg}`
    );
  }
  assert.equal(hasUnparsedDigitsInMenuReply('02'), false);
  assert.equal(hasUnparsedDigitsInMenuReply('Opc 2'), false);

  // Achado 2: Sufixo "k" colado ou espaçado sem falsos positivos em "TV 4k" / "Ouro 18k"
  assert.equal(parseBrlAmountFromText('pix de 5 k'), 5000);
  assert.equal(parseBrlAmountFromText('pix de 5k'), 5000);
  assert.equal(parseBrlAmountFromText('manda 5,5 k no pix'), 5500);
  assert.equal(parseBrlAmountFromText('2 k no pix'), 2000);
  assert.equal(parseBrlAmountFromText('TV 4k no pix'), null);
  assert.equal(parseBrlAmountFromText('TV 4 k, manda pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('Ouro 18k no pix'), null);
  assert.equal(parseBrlAmountFromText('Anel de ouro 18 k, manda pix de 200'), 200);

  // Achado 3: Pedidos explícitos de novo Pix separados por vírgula/ponto sem repetir "pix"/"reais"
  for (const [msg, expected] of [
    ['Já paguei aquele, manda de 100', 100],
    ['Já paguei aquele, faz 100 pra mim', 100],
    ['Deu erro no link, gera de 80', 80],
    ['Venceu o link, manda de 50', 50],
    ['Cancela a atual, gera de 80', 80],
    ['Cancela esse, manda 80', 80],
  ] as Array<[string, number]>) {
    assert.equal(isStatusQueryMessage(msg), false, `Não deveria ser status: ${msg}`);
    assert.equal(isPaymentConfirmationMessage(msg), false, `Não deveria ser pago: ${msg}`);
    assert.equal(parseBrlAmountFromText(msg), expected, `Deveria extrair ${expected} em: ${msg}`);
  }

  // Achado 4: "Transferi!" intransitivo em isPaymentConfirmationMessage e isPostOrderFollowUpMessage
  for (const msg of [
    'Transferi!',
    'Já transferi!',
    'Transferi agora!',
    'Já te transferi!',
    'Pronto, transferi!',
  ]) {
    assert.equal(isPaymentConfirmationMessage(msg), true, `Deveria confirmar pagamento: ${msg}`);
    assert.equal(isPostOrderFollowUpMessage(msg), true, `Deveria aceitar follow-up: ${msg}`);
  }
  assert.equal(isPaymentConfirmationMessage('Transferi os arquivos'), false);

  // Achado 5: Cobrança a maior em 3ª pessoa, bloqueio cautelar e destinatário errado
  for (const msg of [
    'Cobrou 50 a mais no pix',
    'Veio cobrando 50 a mais no pix',
    'Me cobraram 50 a mais no pix',
    'Caiu no bloqueio cautelar o pix de 500',
    'Deu bloqueio no pix de 500',
    'Fiz o pix de 50 pra conta errada',
    'Mandei os 50 pra pessoa errada no pix',
    'Foi 50 pra conta errada no pix',
  ]) {
    assert.equal(isStatusQueryMessage(msg), true, `Deveria ser status: ${msg}`);
    assert.equal(parseBrlAmountFromText(msg), null, `Não deveria cobrar: ${msg}`);
  }

  // Achado 6: Propostas/pechinchas ("Aceita 80?", "80 no pix fecha?") e pagamento parcial/escalonado
  for (const msg of [
    'Aceita 80 no pix?',
    'Topa 80 no pix?',
    'Por 80 no pix fecha?',
    '80 no pix fecha?',
    'R$ 80 no pix rola?',
    'Pago 50 hoje e o resto amanhã no pix?',
    'Posso dar 50 de sinal no pix?',
    'Aceita 50 de entrada no pix?',
    'Me cobra 50 a menos no pix?',
  ]) {
    assert.equal(parseBrlAmountFromText(msg), null, `Deveria bloquear proposta: ${msg}`);
  }

  // Achado 7: Saudações e modais em isExitCommand/isCancelCommand + "hum mil" / "cinqüenta"
  assert.equal(isCancelCommand('Oi, pode cancelar o pix?'), true);
  assert.equal(isCancelCommand('Bom dia, cancela o pix por favor'), true);
  assert.equal(isExitCommand('Quero sair'), true);
  assert.equal(isExitCommand('Pode encerrar'), true);
  assert.equal(isExitCommand('Oi, pode encerrar o atendimento'), true);
  assert.equal(parseBrlAmountFromText('pix de hum mil reais'), 1000);
  assert.equal(parseBrlAmountFromText('Hum, manda pix de 50'), 50);
  assert.equal(parseBrlAmountFromText('pix de cinqüenta reais'), 50);
});
