import http from 'node:http';
import crypto from 'node:crypto';
import { clampInt, SUPPORTED_PROVIDERS } from '../config/env.ts';
import type { AppConfig } from '../config/env.ts';
import { OrderRepository } from '../database/orderRepository.ts';
import { createCryptoProvider } from '../providers/providerFactory.ts';
import { ConversationEngine } from '../services/conversationEngine.ts';
import type {
  FilterMode,
  RuntimeAccountSettings,
  SupportedProviderName,
} from '../types/domain.ts';
import type { BaileysDirectManager } from '../whatsapp/baileysManager.ts';
import { renderDashboardHtml } from './dashboardHtml.ts';

const MAX_BODY_BYTES = 256 * 1024;
const SESSION_COOKIE_NAME = 'robo_admin_sess';
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const LOGIN_WINDOW_MS = 5 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS_PER_IP = 5;
const MAX_GLOBAL_LOGIN_FAILURES = 30;
const MAX_TRACKED_LOGIN_IPS = 2_000;

class PayloadTooLargeError extends Error {}
class BadJsonError extends Error {}

function scryptAsync(password: string, salt: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

async function hashPasswordAsync(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await scryptAsync(password, salt);
  return `${salt}:${derived.toString('hex')}`;
}

async function verifyPasswordHashAsync(password: string, storedHash: string): Promise<boolean> {
  const [salt, keyHex] = storedHash.split(':');
  if (!salt || !keyHex || !/^[0-9a-f]{128}$/i.test(keyHex)) return false;
  const derived = await scryptAsync(password, salt);
  const keyBuf = Buffer.from(keyHex, 'hex');
  if (derived.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derived, keyBuf);
}

/**
 * Comparação em tempo constante via SHA-256 (não vaza tamanho da string por timing).
 */
function safeEqualStrings(a: string, b: string): boolean {
  const hashA = crypto.createHash('sha256').update(a, 'utf8').digest();
  const hashB = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

function maskPhoneForUi(phone: string): string {
  if (phone.length <= 6) return phone;
  return `${phone.slice(0, 4)}****${phone.slice(-4)}`;
}

/**
 * Mascara chaves secretas sem vazar entropia de chaves curtas.
 * Chaves com menos de 20 caracteres exibem apenas marcador opaco.
 */
function maskSecretKeyPreview(rawKey: string): string {
  const k = rawKey.trim();
  if (!k) return '';
  if (k.startsWith('sk_test_') || k.startsWith('sk_live_')) {
    if (k.length < 24) return '•••••••• (Chave salva)';
    return `${k.slice(0, 8)}••••${k.slice(-4)}`;
  }
  if (k.length < 20) return '•••••••• (Chave salva)';
  return `${k.slice(0, 4)}••••${k.slice(-4)}`;
}

function validateAllowedPhoneInput(
  raw: unknown
): { ok: true; cleanDigits?: string } | { ok: false; error: string } {
  if (raw === undefined || raw === null) {
    return { ok: true, cleanDigits: undefined };
  }
  if (typeof raw !== 'string' && typeof raw !== 'number') {
    return { ok: false, error: 'Formato inválido para o campo de telefone.' };
  }
  const trimmed = String(raw).trim();
  if (trimmed === '') {
    return { ok: true, cleanDigits: '' };
  }
  const digits = trimmed.replace(/\D/g, '');
  if (digits.length < 10 || digits.length > 15) {
    return {
      ok: false,
      error:
        'Informe o telefone completo com DDI/DDD (10 a 15 dígitos, ex: 5511999998888) ou deixe o campo em branco.',
    };
  }
  return { ok: true, cleanDigits: digits };
}

function isOptionalStringField(val: unknown): val is string | undefined | null {
  return val === undefined || val === null || typeof val === 'string';
}

function extractClientIp(req: http.IncomingMessage): string {
  // No Render/Cloudflare, o ÚLTIMO IP em X-Forwarded-For é o anexado pelo proxy reverso confiável
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    const parts = xff
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (parts.length > 0) {
      return parts[parts.length - 1];
    }
  }
  return req.socket.remoteAddress || 'unknown';
}

function isCrossSiteRequest(req: http.IncomingMessage): boolean {
  const secFetchSite = req.headers['sec-fetch-site'];
  if (secFetchSite === 'cross-site') {
    return true;
  }
  const origin = req.headers.origin;
  const host = req.headers.host;
  if (typeof origin === 'string' && origin && typeof host === 'string' && host) {
    try {
      const originHost = new URL(origin).host.toLowerCase();
      if (originHost !== host.toLowerCase()) {
        return true;
      }
    } catch {
      return true;
    }
  }
  return false;
}

export function createAppHttpServer(params: {
  config: AppConfig;
  repository: OrderRepository;
  engine: ConversationEngine;
  baileys?: BaileysDirectManager;
}): http.Server {
  const { config, repository, engine, baileys } = params;
  const sessionSigningSecret = crypto.randomBytes(32).toString('hex');
  const loginAttempts = new Map<string, { count: number; resetAt: number }>();
  let globalLoginFailWindow = { count: 0, resetAt: 0 };
  let setupInProgress = false;
  let loginQueue: Promise<void> = Promise.resolve();
  let pendingLoginVerifications = 0;
  const MAX_PENDING_LOGIN_VERIFICATIONS = 10;

  const isIpOrGlobalRateLimited = (clientIp: string, ts: number): boolean => {
    pruneLoginAttempts(ts);
    if (ts >= globalLoginFailWindow.resetAt) {
      globalLoginFailWindow = { count: 0, resetAt: ts + LOGIN_WINDOW_MS };
    }
    const currentAttempt = loginAttempts.get(clientIp);
    return (
      globalLoginFailWindow.count >= MAX_GLOBAL_LOGIN_FAILURES ||
      Boolean(
        currentAttempt &&
          ts < currentAttempt.resetAt &&
          currentAttempt.count >= MAX_LOGIN_ATTEMPTS_PER_IP
      )
    );
  };

  const recordLoginFailure = (clientIp: string, ts: number): void => {
    if (ts >= globalLoginFailWindow.resetAt) {
      globalLoginFailWindow = { count: 0, resetAt: ts + LOGIN_WINDOW_MS };
    }
    globalLoginFailWindow.count += 1;
    const latest = loginAttempts.get(clientIp);
    const prevCount = latest && ts < latest.resetAt ? latest.count : 0;
    const resetAt = latest && ts < latest.resetAt ? latest.resetAt : ts + LOGIN_WINDOW_MS;
    loginAttempts.set(clientIp, {
      count: prevCount + 1,
      resetAt,
    });
  };

  const getRuntimeDefaults = (): RuntimeAccountSettings => ({
    provider: config.cryptoProvider,
    apiKey: getDefaultApiKey(config.cryptoProvider),
    webhookSecret: getDefaultWebhookSecret(config.cryptoProvider),
    walletAddress: config.walletAddress,
    walletAsset: config.walletAsset,
    walletNetwork: config.walletNetwork,
    pixExpirationMinutes: config.pixExpirationMinutes,
    adminWhatsappPhone: config.adminWhatsappPhone,
    waFilterMode: 'keyword_only',
    waAllowedTestPhone: '',
  });

  const pruneLoginAttempts = (now: number): void => {
    for (const [ip, entry] of loginAttempts) {
      if (now >= entry.resetAt) {
        loginAttempts.delete(ip);
      }
    }
    while (loginAttempts.size >= MAX_TRACKED_LOGIN_IPS) {
      const oldestIp = loginAttempts.keys().next().value;
      if (oldestIp === undefined) break;
      loginAttempts.delete(oldestIp);
    }
  };

  const getDefaultWebhookSecret = (prov: SupportedProviderName): string => {
    if (prov === 'depixapp') return config.depixapp.webhookSecret;
    if (prov === 'hodle') return config.hodle.webhookSecret;
    if (prov === 'noxpay') return config.noxpay.webhookSecret;
    return '';
  };

  const getDefaultApiKey = (prov: SupportedProviderName): string => {
    if (prov === 'depixapp') return config.depixapp.apiKey;
    if (prov === 'hodle') return config.hodle.apiKey;
    if (prov === 'noxpay') return config.noxpay.apiKey;
    return '';
  };

  const getEffectiveAccount = (): RuntimeAccountSettings => {
    const saved = repository.getRuntimeSettings(getRuntimeDefaults());
    return {
      ...saved,
      apiKey: saved.apiKey?.trim() || getDefaultApiKey(saved.provider),
      webhookSecret: saved.webhookSecret?.trim() || getDefaultWebhookSecret(saved.provider),
    };
  };

  const isPasswordConfigured = (): boolean => {
    if (config.adminPassword) return true;
    const acc = getEffectiveAccount();
    return Boolean(acc.adminPinHash);
  };

  const verifyAdminPasswordAsync = async (candidate: string): Promise<boolean> => {
    if (!candidate) return false;
    if (config.adminPassword) {
      return safeEqualStrings(candidate, config.adminPassword);
    }
    const acc = getEffectiveAccount();
    if (!acc.adminPinHash) return false;
    return verifyPasswordHashAsync(candidate, acc.adminPinHash);
  };

  const createSessionToken = (): string => {
    const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
    const nonce = crypto.randomBytes(12).toString('hex');
    const payload = `${exp}.${nonce}`;
    const sig = crypto
      .createHmac('sha256', sessionSigningSecret)
      .update(payload)
      .digest('hex');
    return `${payload}.${sig}`;
  };

  const verifySessionToken = (token: string): boolean => {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const [expStr, nonce, sig] = parts;
    if (!/^\d+$/.test(expStr) || !nonce || !/^[0-9a-f]{64}$/.test(sig)) return false;
    const exp = Number(expStr);
    if (Math.floor(Date.now() / 1000) > exp) return false;

    const expectedSig = crypto
      .createHmac('sha256', sessionSigningSecret)
      .update(`${expStr}.${nonce}`)
      .digest('hex');
    return safeEqualStrings(sig, expectedSig);
  };

  /**
   * Aceita APENAS tokens de sessão assinados (cookie ou Bearer), exigindo que
   * qualquer tentativa de senha passe obrigatoriamente pelo rate-limit de `/api/auth/login`!
   */
  const isRequestAuthenticated = (req: http.IncomingMessage): boolean => {
    if (!isPasswordConfigured()) return false;

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const bearer = authHeader.slice(7).trim();
      if (verifySessionToken(bearer)) {
        return true;
      }
    }

    const cookieHeader = req.headers.cookie || '';
    const cookies = cookieHeader.split(';').map((c) => c.trim());
    for (const c of cookies) {
      if (c.startsWith(`${SESSION_COOKIE_NAME}=`)) {
        try {
          const val = decodeURIComponent(c.slice(SESSION_COOKIE_NAME.length + 1));
          if (verifySessionToken(val)) return true;
        } catch {
          return false;
        }
      }
    }
    return false;
  };

  const buildSessionCookie = (req: http.IncomingMessage, token: string, maxAge: number): string => {
    const proto = String(req.headers['x-forwarded-proto'] || '');
    const isSecure = proto === 'https' || config.publicBaseUrl.startsWith('https://');
    const parts = [
      `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${maxAge}`,
    ];
    if (isSecure) parts.push('Secure');
    return parts.join('; ');
  };

  return http.createServer(async (req, res) => {
    try {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'no-referrer');

      let pathname = '/';
      try {
        const rawReqUrl = typeof req.url === 'string' ? req.url : '/';
        if (!rawReqUrl.startsWith('/')) {
          sendJson(res, 400, { error: 'URL de requisição inválida.' });
          return;
        }
        pathname = new URL(rawReqUrl, 'http://localhost').pathname;
      } catch {
        sendJson(res, 400, { error: 'URL de requisição malformada.' });
        return;
      }
      const method = req.method || 'GET';

      if (method === 'GET' && pathname === '/') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy':
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
        });
        res.end(renderDashboardHtml());
        return;
      }

      if (method === 'GET' && pathname === '/health') {
        sendJson(res, 200, { status: 'ok' });
        return;
      }

      // Proteção CSRF em todas as mutações POST sob `/api/*`
      if (method === 'POST' && pathname.startsWith('/api/') && isCrossSiteRequest(req)) {
        sendJson(res, 403, { error: 'Requisição cross-origin bloqueada (CSRF).' });
        return;
      }

      // ==================== AUTENTICAÇÃO DO PAINEL ====================

      if (method === 'GET' && pathname === '/api/auth/status') {
        const configured = isPasswordConfigured();
        const authenticated = isRequestAuthenticated(req);
        sendJson(res, 200, {
          needsSetup: !configured,
          authenticated,
        });
        return;
      }

      if (method === 'POST' && pathname === '/api/auth/setup') {
        if (isPasswordConfigured() || setupInProgress) {
          sendJson(res, 403, { error: 'A senha do painel já foi configurada.' });
          return;
        }
        setupInProgress = true;
        try {
          const body = parseJsonObject(await readRawBody(req));
          if (typeof body.password !== 'string') {
            sendJson(res, 400, { error: 'Escolha uma senha em texto entre 4 e 128 caracteres.' });
            return;
          }
          const newPassword = body.password.trim();
          if (newPassword.length < 4 || newPassword.length > 128) {
            sendJson(res, 400, { error: 'Escolha uma senha entre 4 e 128 caracteres.' });
            return;
          }

          if (config.adminPassword) {
            sendJson(res, 403, { error: 'A senha do painel já foi configurada.' });
            return;
          }

          const pinHash = await hashPasswordAsync(newPassword);
          const created = repository.trySetupInitialAdminPinHash(pinHash, getRuntimeDefaults());
          if (!created) {
            sendJson(res, 403, { error: 'A senha do painel já foi configurada.' });
            return;
          }

          const token = createSessionToken();
          res.setHeader('Set-Cookie', buildSessionCookie(req, token, SESSION_TTL_SECONDS));
          sendJson(res, 200, { ok: true, token });
          return;
        } finally {
          setupInProgress = false;
        }
      }

      if (method === 'POST' && pathname === '/api/auth/login') {
        const clientIp = extractClientIp(req);
        if (
          isIpOrGlobalRateLimited(clientIp, Date.now()) ||
          pendingLoginVerifications >= MAX_PENDING_LOGIN_VERIFICATIONS
        ) {
          sendJson(res, 429, {
            error: 'Muitas tentativas incorretas. Aguarde 5 minutos e tente novamente.',
          });
          return;
        }

        const body = parseJsonObject(await readRawBody(req));

        pendingLoginVerifications += 1;
        const runSerializedLogin = loginQueue
          .catch(() => {})
          .then(async () => {
            const ts = Date.now();
            if (isIpOrGlobalRateLimited(clientIp, ts)) {
              sendJson(res, 429, {
                error: 'Muitas tentativas incorretas. Aguarde 5 minutos e tente novamente.',
              });
              return;
            }

            if (typeof body.password !== 'string') {
              recordLoginFailure(clientIp, ts);
              sendJson(res, 400, { error: 'Formato de senha inválido.' });
              return;
            }

            const password = body.password.trim();
            if (!password || password.length > 128) {
              recordLoginFailure(clientIp, ts);
              sendJson(res, 401, { error: 'Senha incorreta.' });
              return;
            }

            const valid = await verifyAdminPasswordAsync(password);
            if (!valid) {
              recordLoginFailure(clientIp, Date.now());
              sendJson(res, 401, { error: 'Senha incorreta.' });
              return;
            }

            loginAttempts.delete(clientIp);
            const token = createSessionToken();
            res.setHeader('Set-Cookie', buildSessionCookie(req, token, SESSION_TTL_SECONDS));
            sendJson(res, 200, { ok: true, token });
          });

        loginQueue = runSerializedLogin;
        try {
          await runSerializedLogin;
        } finally {
          pendingLoginVerifications -= 1;
        }
        return;
      }

      if (method === 'POST' && pathname === '/api/auth/logout') {
        res.setHeader('Set-Cookie', buildSessionCookie(req, '', 0));
        sendJson(res, 200, { ok: true });
        return;
      }

      // ==================== WEBHOOKS DOS GATEWAYS CRIPTO ====================

      if (method === 'POST' && pathname.startsWith('/webhooks/')) {
        const activeProvider = engine.getCryptoProvider();
        const providerPath = pathname.replace('/webhooks/', '').toLowerCase();
        if (providerPath !== activeProvider.name) {
          sendJson(res, 400, { error: 'Provedor de webhook divergente do ativo.' });
          return;
        }

        const rawBody = await readRawBody(req);
        const validSig = activeProvider.verifyWebhookSignature(rawBody, req.headers);
        if (!validSig) {
          sendJson(res, 401, { error: 'Assinatura HMAC inválida ou ausente.' });
          return;
        }

        const headerEventId =
          typeof req.headers['x-depix-event-id'] === 'string'
            ? req.headers['x-depix-event-id'].trim()
            : undefined;
        if (headerEventId && repository.hasWebhookEvent(headerEventId)) {
          sendJson(res, 200, { ok: true, duplicate: true });
          return;
        }

        const payload = parseJsonObject(rawBody);
        const settlementEvent = activeProvider.parseWebhookPayload(payload);
        if (!settlementEvent) {
          sendJson(res, 200, { ignored: true });
          return;
        }
        if (headerEventId && settlementEvent.eventId && headerEventId !== settlementEvent.eventId) {
          sendJson(res, 400, {
            error: 'Cabeçalho X-DePix-Event-Id diverge do event_id assinado no payload.',
          });
          return;
        }
        if (headerEventId && !settlementEvent.eventId) {
          settlementEvent.eventId = headerEventId;
        }

        const result = await engine.handleSettlementWebhook(settlementEvent);
        sendJson(res, 200, { ok: true, matched: result.matched, changed: result.changed });
        return;
      }

      // ==================== ROTAS AUTENTICADAS ====================

      if (pathname.startsWith('/api/') && !isRequestAuthenticated(req)) {
        sendJson(res, 401, { error: 'Acesso não autorizado. Faça login no painel.' });
        return;
      }

      if (method === 'GET' && pathname === '/api/account') {
        const acc = getEffectiveAccount();
        const hasKey = Boolean(acc.apiKey && acc.apiKey.trim().length > 0);
        const hasWebhookSecret = Boolean(acc.webhookSecret && acc.webhookSecret.trim().length > 0);
        sendJson(res, 200, {
          provider: acc.provider,
          walletAddress: acc.provider === 'depixapp' ? '' : acc.walletAddress,
          walletAsset: acc.provider === 'depixapp' ? 'DEPIX' : acc.walletAsset,
          walletNetwork: acc.provider === 'depixapp' ? 'LIQUID' : acc.walletNetwork,
          pixExpirationMinutes: acc.pixExpirationMinutes,
          adminWhatsappPhone: acc.adminWhatsappPhone,
          hasApiKey: hasKey,
          hasWebhookSecret,
          isTestKey: hasKey && acc.apiKey.trim().startsWith('sk_test_'),
          apiKeyPreview: hasKey ? maskSecretKeyPreview(acc.apiKey) : '',
        });
        return;
      }

      if (method === 'POST' && pathname === '/api/account') {
        const body = parseJsonObject(await readRawBody(req));
        if (
          !isOptionalStringField(body.provider) ||
          !isOptionalStringField(body.apiKey) ||
          !isOptionalStringField(body.webhookSecret) ||
          !isOptionalStringField(body.walletAsset) ||
          !isOptionalStringField(body.walletNetwork) ||
          !isOptionalStringField(body.walletAddress) ||
          (body.adminWhatsappPhone !== undefined &&
            body.adminWhatsappPhone !== null &&
            typeof body.adminWhatsappPhone !== 'string' &&
            typeof body.adminWhatsappPhone !== 'number')
        ) {
          sendJson(res, 400, { error: 'Formato inválido nos campos de configuração.' });
          return;
        }

        const current = getEffectiveAccount();

        const rawProv = (body.provider ? body.provider.trim() : current.provider).toLowerCase();
        if (!SUPPORTED_PROVIDERS.includes(rawProv as SupportedProviderName)) {
          sendJson(res, 400, { error: 'Provedor inválido.' });
          return;
        }
        const provider = rawProv as SupportedProviderName;

        const providerChanged = provider !== current.provider;
        const newApiKey =
          typeof body.apiKey === 'string' && body.apiKey.trim() !== ''
            ? body.apiKey.trim()
            : providerChanged
              ? getDefaultApiKey(provider)
              : current.apiKey;

        const newWebhookSecret =
          typeof body.webhookSecret === 'string' && body.webhookSecret.trim() !== ''
            ? body.webhookSecret.trim()
            : providerChanged
              ? getDefaultWebhookSecret(provider)
              : current.webhookSecret;

        const fallbackNonDepixAsset =
          current.walletAsset && current.walletAsset !== 'DEPIX' ? current.walletAsset : 'USDT';
        const fallbackNonDepixNetwork =
          current.walletNetwork && current.walletNetwork !== 'LIQUID'
            ? current.walletNetwork
            : 'POLYGON';

        const walletAsset =
          provider === 'depixapp'
            ? 'DEPIX'
            : typeof body.walletAsset === 'string' && body.walletAsset.trim() !== ''
              ? body.walletAsset.trim().toUpperCase()
              : fallbackNonDepixAsset;

        const walletNetwork =
          provider === 'depixapp'
            ? 'LIQUID'
            : typeof body.walletNetwork === 'string' && body.walletNetwork.trim() !== ''
              ? body.walletNetwork.trim().toUpperCase()
              : fallbackNonDepixNetwork;

        const walletAddress =
          provider === 'depixapp'
            ? ''
            : typeof body.walletAddress === 'string'
              ? body.walletAddress.trim()
              : current.walletAddress;

        const safeExpMinutes = clampInt(
          body.pixExpirationMinutes,
          clampInt(current.pixExpirationMinutes, 15, 5, 20),
          5,
          20
        );

        const saved = repository.saveRuntimeSettings({
          ...current,
          provider,
          apiKey: newApiKey,
          webhookSecret: newWebhookSecret,
          walletAddress,
          walletAsset,
          walletNetwork,
          pixExpirationMinutes: safeExpMinutes,
          adminWhatsappPhone:
            body.adminWhatsappPhone !== undefined && body.adminWhatsappPhone !== null
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
          sendJson(res, 400, { error: 'Gerenciador WhatsApp QR não habilitado.' });
          return;
        }
        const rawBody = await readRawBody(req);
        if (rawBody.trim()) {
          const body = parseJsonObject(rawBody);
          const phoneCheck = validateAllowedPhoneInput(body.allowedTestPhone);
          if (!phoneCheck.ok) {
            sendJson(res, 400, { error: phoneCheck.error });
            return;
          }
          const filterMode: FilterMode | undefined =
            body.filterMode === 'all' || body.filterMode === 'keyword_only'
              ? body.filterMode
              : undefined;
          const updatedWa = baileys.updateFilterSettings({
            filterMode,
            allowedTestPhone: phoneCheck.cleanDigits,
          });

          const currentAcc = getEffectiveAccount();
          repository.saveRuntimeSettings({
            ...currentAcc,
            waFilterMode: updatedWa.filterMode,
            waAllowedTestPhone: updatedWa.allowedTestPhone,
          });
        }
        const status = await baileys.startConnection(true);
        sendJson(res, 200, status);
        return;
      }

      if (method === 'POST' && pathname === '/api/whatsapp/settings') {
        if (!baileys) {
          sendJson(res, 400, { error: 'Gerenciador WhatsApp QR não habilitado.' });
          return;
        }
        const body = parseJsonObject(await readRawBody(req));
        const phoneCheck = validateAllowedPhoneInput(body.allowedTestPhone);
        if (!phoneCheck.ok) {
          sendJson(res, 400, { error: phoneCheck.error });
          return;
        }
        const filterMode: FilterMode | undefined =
          body.filterMode === 'all' || body.filterMode === 'keyword_only'
            ? body.filterMode
            : undefined;
        const status = baileys.updateFilterSettings({
          filterMode,
          allowedTestPhone: phoneCheck.cleanDigits,
        });

        const currentAcc = getEffectiveAccount();
        repository.saveRuntimeSettings({
          ...currentAcc,
          waFilterMode: status.filterMode,
          waAllowedTestPhone: status.allowedTestPhone,
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

      if (method === 'GET' && pathname === '/api/orders') {
        const orders = repository.listRecentOrders(50).map((o) => ({
          id: o.id,
          externalId: o.externalId,
          provider: o.provider,
          customerPhoneMasked: maskPhoneForUi(o.customerPhone),
          amountBrl: o.amountBrl,
          cryptoAsset: o.cryptoAsset,
          cryptoNetwork: o.cryptoNetwork,
          status: o.status,
          createdAt: o.createdAt,
          expiresAt: o.expiresAt,
        }));
        sendJson(res, 200, orders);
        return;
      }

      if (method === 'POST' && pathname.startsWith('/api/simulator/pay/')) {
        let orderId = '';
        try {
          orderId = decodeURIComponent(pathname.replace('/api/simulator/pay/', ''));
        } catch {
          sendJson(res, 400, { error: 'ID de pedido malformado.' });
          return;
        }
        const order = repository.getOrderById(orderId);
        if (!order || order.status !== 'PENDING') {
          sendJson(res, 400, { error: 'Pedido inválido ou já processado.' });
          return;
        }

        if (order.provider !== 'mock') {
          sendJson(res, 403, {
            error: 'Simulação manual permitida apenas no Modo Teste Interno.',
          });
          return;
        }

        const result = await engine.handleSettlementWebhook({
          provider: order.provider,
          providerChargeId: order.providerChargeId,
          externalId: order.externalId,
          newStatus: 'SETTLED_CRYPTO',
          txHash: `tx_sim_${crypto.randomBytes(12).toString('hex')}`,
          cryptoAmount: order.estimatedCryptoAmount,
          rawEventName: 'SIMULATOR_CLICK_PAY',
        });
        sendJson(res, 200, { ok: true, result });
        return;
      }

      sendJson(res, 404, { error: 'Rota não encontrada.' });
    } catch (error) {
      if (error instanceof PayloadTooLargeError) {
        if (!res.headersSent) {
          res.writeHead(413, {
            'Content-Type': 'application/json; charset=utf-8',
            Connection: 'close',
          });
          res.end(
            JSON.stringify({ error: 'Requisição excede o tamanho máximo permitido (256 KB).' }),
            () => req.destroy()
          );
        } else {
          req.destroy();
        }
        return;
      }
      if (error instanceof BadJsonError) {
        sendJson(res, 400, { error: 'Formato JSON inválido na requisição.' });
        return;
      }
      const msg = error instanceof Error ? error.message : String(error);
      console.error('[HTTP Server] Erro interno:', msg);
      sendJson(res, 500, { error: 'Erro interno do servidor.' });
    }
  });
}

function readRawBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let rejected = false;

    req.on('data', (chunk: Buffer) => {
      if (rejected) return;
      totalBytes += chunk.length;
      if (totalBytes > MAX_BODY_BYTES) {
        rejected = true;
        req.pause();
        reject(new PayloadTooLargeError('Payload Too Large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!rejected) {
        resolve(Buffer.concat(chunks).toString('utf8'));
      }
    });
    req.on('error', (err) => {
      if (!rejected) reject(err);
    });
  });
}

function parseJsonObject(raw: string): Record<string, unknown> {
  if (!raw || !raw.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new BadJsonError('Malformed JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new BadJsonError('JSON root must be an object');
  }
  return parsed as Record<string, unknown>;
}

function sendJson(res: http.ServerResponse, statusCode: number, data: unknown): void {
  if (res.headersSent) return;
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}
