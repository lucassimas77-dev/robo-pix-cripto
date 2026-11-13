import http from 'node:http';
import crypto from 'node:crypto';
import type { AppConfig } from '../config/env.ts';
import { OrderRepository } from '../database/orderRepository.ts';
import { createCryptoProvider } from '../providers/providerFactory.ts';
import { ConversationEngine } from '../services/conversationEngine.ts';
import type { RuntimeAccountSettings, SupportedProviderName } from '../types/domain.ts';
import type { BaileysDirectManager, FilterMode } from '../whatsapp/baileysManager.ts';
import { renderDashboardHtml } from './dashboardHtml.ts';

export function createAppHttpServer(params: {
  config: AppConfig;
  repository: OrderRepository;
  engine: ConversationEngine;
  baileys?: BaileysDirectManager;
}): http.Server {
  const { config, repository, engine, baileys } = params;

  const getEffectiveAccount = (): RuntimeAccountSettings =>
    repository.getRuntimeSettings({
      provider: config.cryptoProvider,
      apiKey:
        config.cryptoProvider === 'depixapp'
          ? config.depixapp.apiKey
          : config.cryptoProvider === 'hodle'
            ? config.hodle.apiKey
            : config.cryptoProvider === 'noxpay'
              ? config.noxpay.apiKey
              : '',
      webhookSecret: '',
      walletAddress: config.walletAddress,
      walletAsset: config.walletAsset,
      walletNetwork: config.walletNetwork,
      pixExpirationMinutes: config.pixExpirationMinutes,
      adminWhatsappPhone: config.adminWhatsappPhone,
    });

  return http.createServer(async (req, res) => {
    try {
      const urlObj = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const pathname = urlObj.pathname;
      const method = req.method || 'GET';

      // 1. Painel Simples em 3 Passos (Autoatendimento para você ou seu amigo)
      if (method === 'GET' && pathname === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(renderDashboardHtml());
        return;
      }

      if (method === 'GET' && pathname === '/health') {
        const activeProvider = engine.getCryptoProvider();
        sendJson(res, 200, {
          status: 'ok',
          provider: activeProvider.name,
          whatsappQrState: baileys?.getStatus().state ?? 'DISABLED',
        });
        return;
      }

      // ==================== PASSO 1: CONFIGURAÇÃO DA CONTA & CARTEIRA PELA TELA ====================

      if (method === 'GET' && pathname === '/api/account') {
        const acc = getEffectiveAccount();
        sendJson(res, 200, {
          ...acc,
          hasApiKey: Boolean(acc.apiKey && acc.apiKey.trim().length > 0),
          // Mascara a chave para segurança visual
          apiKeyPreview: acc.apiKey ? `${acc.apiKey.slice(0, 6)}...${acc.apiKey.slice(-4)}` : '',
        });
        return;
      }

      if (method === 'POST' && pathname === '/api/account') {
        const rawBody = await readRawBody(req);
        const body = JSON.parse(rawBody || '{}') as Record<string, unknown>;
        const current = getEffectiveAccount();

        const provider = (String(body.provider || current.provider).toLowerCase()) as SupportedProviderName;
        const newApiKey =
          body.apiKey !== undefined && String(body.apiKey).trim() !== ''
            ? String(body.apiKey).trim()
            : current.apiKey;

        const saved = repository.saveRuntimeSettings({
          provider,
          apiKey: newApiKey,
          webhookSecret:
            body.webhookSecret !== undefined
              ? String(body.webhookSecret).trim()
              : current.webhookSecret,
          walletAddress:
            body.walletAddress !== undefined
              ? String(body.walletAddress).trim()
              : current.walletAddress,
          walletAsset:
            body.walletAsset !== undefined
              ? String(body.walletAsset).trim().toUpperCase()
              : current.walletAsset,
          walletNetwork:
            body.walletNetwork !== undefined
              ? String(body.walletNetwork).trim().toUpperCase()
              : current.walletNetwork,
          pixExpirationMinutes: Math.max(
            5,
            Number(body.pixExpirationMinutes || current.pixExpirationMinutes || 15)
          ),
          adminWhatsappPhone:
            body.adminWhatsappPhone !== undefined
              ? String(body.adminWhatsappPhone).replace(/\D/g, '')
              : current.adminWhatsappPhone,
        });

        const updatedConfig: AppConfig = {
          ...config,
          cryptoProvider: saved.provider,
          walletAddress: saved.walletAddress,
          walletAsset: saved.walletAsset,
          walletNetwork: saved.walletNetwork,
          pixExpirationMinutes: saved.pixExpirationMinutes,
          adminWhatsappPhone: saved.adminWhatsappPhone,
        };

        const newProviderInstance = createCryptoProvider(updatedConfig, saved);
        engine.updateRuntimeAccount(updatedConfig, newProviderInstance);

        sendJson(res, 200, { ok: true, provider: saved.provider });
        return;
      }

      // ==================== PASSO 2: WHATSAPP QR CODE ====================

      if (method === 'GET' && pathname === '/api/whatsapp/status') {
        sendJson(
          res,
          200,
          baileys
            ? baileys.getStatus()
            : { state: 'DISCONNECTED', filterMode: 'keyword_only', allowedTestPhone: '' }
        );
        return;
      }

      if (method === 'POST' && pathname === '/api/whatsapp/connect') {
        if (!baileys) {
          sendJson(res, 400, { error: 'Gerenciador Baileys não habilitado.' });
          return;
        }
        const rawBody = await readRawBody(req);
        if (rawBody) {
          const body = JSON.parse(rawBody) as Record<string, unknown>;
          baileys.updateFilterSettings({
            filterMode: body.filterMode as FilterMode | undefined,
            allowedTestPhone:
              body.allowedTestPhone != null ? String(body.allowedTestPhone) : undefined,
          });
        }
        const status = await baileys.startConnection();
        sendJson(res, 200, status);
        return;
      }

      if (method === 'POST' && pathname === '/api/whatsapp/settings') {
        if (!baileys) {
          sendJson(res, 400, { error: 'Gerenciador Baileys não habilitado.' });
          return;
        }
        const rawBody = await readRawBody(req);
        const body = JSON.parse(rawBody || '{}') as Record<string, unknown>;
        const status = baileys.updateFilterSettings({
          filterMode: body.filterMode as FilterMode | undefined,
          allowedTestPhone:
            body.allowedTestPhone != null ? String(body.allowedTestPhone) : undefined,
        });
        sendJson(res, 200, status);
        return;
      }

      if (method === 'POST' && pathname === '/api/whatsapp/disconnect') {
        if (!baileys) {
          sendJson(res, 200, { state: 'DISCONNECTED' });
          return;
        }
        const status = await baileys.disconnect(true);
        sendJson(res, 200, status);
        return;
      }

      // ==================== WEBHOOKS DOS GATEWAYS CRIPTO ====================

      if (method === 'POST' && pathname.startsWith('/webhooks/')) {
        const activeProvider = engine.getCryptoProvider();
        const providerPath = pathname.replace('/webhooks/', '').toLowerCase();
        if (providerPath !== activeProvider.name) {
          sendJson(res, 400, {
            error: `Provedor ativo é '${activeProvider.name}', recebido '${providerPath}'.`,
          });
          return;
        }

        const rawBody = await readRawBody(req);
        const validSig = activeProvider.verifyWebhookSignature(rawBody, req.headers);
        if (!validSig) {
          sendJson(res, 401, { error: 'Assinatura HMAC do webhook inválida.' });
          return;
        }

        const payload = JSON.parse(rawBody || '{}');
        const settlementEvent = activeProvider.parseWebhookPayload(payload);
        if (!settlementEvent) {
          sendJson(res, 200, { ignored: true });
          return;
        }

        const result = await engine.handleSettlementWebhook(settlementEvent);
        sendJson(res, 200, { ok: true, matched: result.matched, changed: result.changed });
        return;
      }

      // ==================== HISTÓRICO DE PEDIDOS & TESTE RÁPIDO ====================

      if (method === 'GET' && pathname === '/api/orders') {
        sendJson(res, 200, repository.listRecentOrders(50));
        return;
      }

      if (method === 'POST' && pathname.startsWith('/api/simulator/pay/')) {
        const orderId = decodeURIComponent(pathname.replace('/api/simulator/pay/', ''));
        const order = repository.getOrderById(orderId);
        if (!order || order.status !== 'PENDING') {
          sendJson(res, 400, { error: 'Pedido inválido ou já processado.' });
          return;
        }

        const result = await engine.handleSettlementWebhook({
          provider: order.provider,
          providerChargeId: order.providerChargeId,
          externalId: order.externalId,
          newStatus: 'SETTLED_CRYPTO',
          txHash: `tx_liquid_${crypto.randomBytes(16).toString('hex')}`,
          cryptoAmount: order.estimatedCryptoAmount,
          rawEventName: 'SIMULATOR_CLICK_PAY',
        });

        sendJson(res, 200, { ok: true, result });
        return;
      }

      sendJson(res, 404, { error: 'Rota não encontrada.' });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      console.error('[HTTP Server] Erro interno:', msg);
      sendJson(res, 500, { error: 'Erro interno do servidor', detail: msg });
    }
  });
}

function readRawBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res: http.ServerResponse, statusCode: number, data: unknown): void {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}
