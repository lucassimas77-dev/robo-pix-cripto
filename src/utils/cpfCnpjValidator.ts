import net from 'node:net';

/**
 * Utilitários de extração segura de valores monetários em Reais (BRL),
 * coerção estrita de tipos/datas UTC, validação de URLs públicas HTTPS e detecção de intenções em português
 * (estritamente O(N), 100% imune a ReDoS).
 */

const MAX_COMMAND_LEN = 500;
const MAX_NLU_LEN = 2_000;
const EDGE_PUNCT_CHARS = new Set([
  ' ',
  '\t',
  '\n',
  '\r',
  '!',
  '?',
  '.',
  '…',
  ',',
  ';',
  ':',
  '-',
]);

const RESERVED_TLDS = new Set([
  'localhost',
  'local',
  'internal',
  'test',
  'invalid',
  'example',
  'lan',
  'home',
  'arpa',
  'onion',
]);

export function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) {
    end--;
  }
  return end === value.length ? value : value.slice(0, end);
}

function stripTrailingDots(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 46) {
    end--;
  }
  return end === value.length ? value : value.slice(0, end);
}

export function asPlainObject(val: unknown): Record<string, unknown> | null {
  if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
    return val as Record<string, unknown>;
  }
  return null;
}

export function safePrimitiveString(val: unknown): string {
  return typeof val === 'string' ? val : '';
}

export function safeOptionalId(val: unknown): string | undefined {
  if (typeof val === 'string') {
    const s = val.trim();
    return s ? s : undefined;
  }
  if (typeof val === 'number' && Number.isFinite(val) && val > 0) {
    return String(val);
  }
  return undefined;
}

export function safePositiveNumber(val: unknown): number | undefined {
  if (typeof val === 'number') {
    return Number.isFinite(val) && val > 0 ? val : undefined;
  }
  if (typeof val === 'string') {
    const trimmed = val.trim();
    if (!trimmed) return undefined;
    const n = Number(trimmed);
    return Number.isFinite(n) && n > 0 ? n : undefined;
  }
  return undefined;
}

function epochNumberToMs(num: number): number {
  if (num >= 1e17) return num / 1_000_000; // nanossegundos -> ms
  if (num >= 1e14) return num / 1_000; // microssegundos -> ms
  if (num < 1e11) return num * 1_000; // segundos -> ms
  return num; // milissegundos
}

function toCanonicalSqlIso(d: Date): string | undefined {
  const ms = d.getTime();
  if (!Number.isFinite(ms)) return undefined;
  const year = d.getUTCFullYear();
  if (year < 2000 || year > 9999) return undefined;
  const iso = d.toISOString();
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(iso) ? iso : undefined;
}

export function normalizeUtcIsoTimestamp(raw: unknown, fallbackIso?: string): string | undefined {
  if (typeof raw === 'number' && Number.isFinite(raw) && raw > 0) {
    const iso = toCanonicalSqlIso(new Date(epochNumberToMs(raw)));
    if (iso) return iso;
  } else if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (/^\d{10,19}$/.test(trimmed)) {
      const iso = toCanonicalSqlIso(new Date(epochNumberToMs(Number(trimmed))));
      if (iso) return iso;
    } else if (trimmed) {
      const iso = toCanonicalSqlIso(new Date(trimmed));
      if (iso) return iso;
    }
  }
  return fallbackIso;
}

function isPublicGlobalIpv4(host: string): boolean {
  const parts = host.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  const [a, b, c] = parts;
  if (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  ) {
    return false;
  }
  return true;
}

function parseIpv6Words(host: string): number[] | null {
  let normalized = host.toLowerCase();
  // Trata sufixo IPv4 embutido (ex: ::ffff:127.0.0.1)
  const lastColon = normalized.lastIndexOf(':');
  if (lastColon !== -1 && normalized.slice(lastColon + 1).includes('.')) {
    const ipv4Part = normalized.slice(lastColon + 1);
    if (!net.isIPv4(ipv4Part)) return null;
    const [o1, o2, o3, o4] = ipv4Part.split('.').map(Number);
    const hi = ((o1 << 8) | o2).toString(16);
    const lo = ((o3 << 8) | o4).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const dblParts = normalized.split('::');
  if (dblParts.length > 2) return null;

  const left = dblParts[0] ? dblParts[0].split(':') : [];
  const right = dblParts.length === 2 && dblParts[1] ? dblParts[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if ((dblParts.length === 1 && missing !== 0) || (dblParts.length === 2 && missing < 1)) {
    return null;
  }

  const full = [...left, ...Array<string>(dblParts.length === 2 ? missing : 0).fill('0'), ...right];
  if (full.length !== 8) return null;

  const words: number[] = [];
  for (const h of full) {
    if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
    words.push(parseInt(h, 16));
  }
  return words;
}

export function isPublicHttpsWebhookUrl(rawUrl: string): boolean {
  if (typeof rawUrl !== 'string' || !rawUrl.startsWith('https://')) return false;
  try {
    const u = new URL(rawUrl);
    if (u.protocol !== 'https:') return false;
    const rawHost = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const host = stripTrailingDots(rawHost);
    if (!host) return false;

    if (net.isIPv4(host)) {
      return isPublicGlobalIpv4(host);
    }

    if (net.isIPv6(host)) {
      const words = parseIpv6Words(host);
      if (!words) return false;
      // Somente Global Unicast `2000::/3` é roteável na Internet pública (exclui ::1, ::7f00:1, fe80::/10, fc00::/7, ff00::/8, 64:ff9b::, 100::)
      if ((words[0] & 0xe000) !== 0x2000) return false;
      // Exclui Teredo (2001:0::/32), Benchmarking (2001:2::/48), Documentação (2001:db8::/32) e 6to4 (2002::/16)
      if (
        words[0] === 0x2001 &&
        (words[1] === 0x0000 || (words[1] === 0x0002 && words[2] === 0x0000) || words[1] === 0x0db8)
      ) {
        return false;
      }
      if (words[0] === 0x2002) return false;
      return true;
    }

    const labels = host.split('.');
    if (labels.length < 2) return false;
    const tld = labels[labels.length - 1];
    if (RESERVED_TLDS.has(tld)) return false;
    if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/.test(tld)) return false;

    for (const label of labels) {
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

export function onlyDigits(value: string): string {
  return value.replace(/\D/g, '');
}

function parseNumericToken(token: string): number | null {
  const t = token.trim();
  if (!t) return null;

  let normalized: string;
  if (/^\d{1,3}(?:\.\d{3})+,\d{1,2}$/.test(t)) {
    normalized = t.replace(/\./g, '').replace(',', '.');
  } else if (/^\d{1,3}(?:\.\d{3})+$/.test(t)) {
    normalized = t.replace(/\./g, '');
  } else if (/^\d+,\d{1,2}$/.test(t)) {
    normalized = t.replace(',', '.');
  } else if (/^\d+\.\d{1,2}$/.test(t)) {
    normalized = t;
  } else if (/^\d+$/.test(t)) {
    if (t.length >= 8) return null;
    normalized = t;
  } else {
    return null;
  }

  const amount = Number(normalized);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 10_000_000) {
    return null;
  }
  return Math.round(amount * 100) / 100;
}

const NUM_CORE =
  '(?:\\d{1,3}(?:\\.\\d{3})+,\\d{1,2}|\\d{1,3}(?:\\.\\d{3})+(?![.,]\\d|\\d)|\\d+,\\d{1,2}(?!\\d)|\\d+\\.\\d{1,2}(?![.,]\\d|\\d)|\\d+)';
const NUM_LEFT = '(?<![-\\w@/,]|\\d\\.)';
const NUM_RIGHT = '(?![.,]\\d|\\d|[-\\w]|[ \\t]*%|\\.[a-zA-Z]|\\/[a-zA-Z0-9])';

export function parseBrlAmountFromText(text: string): number | null {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) return null;
  const cleaned = text.trim();
  if (!cleaned) return null;

  // Passo 0 (O(N)): remove tokens de URL, e-mail, @handle e IDs prd_/chk_
  const filteredWords = cleaned
    .split(/\s+/)
    .filter((tok) => {
      const low = tok.toLowerCase();
      if (low.includes('@')) return false;
      if (
        low.includes('://') ||
        low.startsWith('www.') ||
        low.includes('.com') ||
        low.includes('.app') ||
        low.includes('.net') ||
        low.includes('.org') ||
        low.includes('.br/') ||
        low.includes('prd_') ||
        low.includes('chk_')
      ) {
        return false;
      }
      return true;
    })
    .join(' ');

  if (!filteredWords) return null;

  const withoutContactsAndDates = filteredWords
    // 1) Remove documentos estruturados (CPF, CNPJ numérico ou alfanumérico, CEP pontuado, RG) e datas ANTES de pares hifenizados!
    .replace(/(?<![A-Za-z0-9])[A-Za-z0-9]{2}\.[A-Za-z0-9]{3}\.[A-Za-z0-9]{3}\/[A-Za-z0-9]{4}-\d{2}(?!\d)/g, ' ')
    .replace(/(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)/g, ' ')
    .replace(/(?<!\d)\d{2}\.\d{3}-\d{3}(?!\d)/g, ' ')
    .replace(/(?<!\d)\d{1,2}\.\d{3}\.\d{3}-[\dxX]\b/g, ' ')
    .replace(/\b\d{1,2}\/\d{1,2}(?:\/\d{2,4})?\b/g, ' ')
    .replace(/(?<!\d)(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}-\d{1,2}-\d{2,4})(?!\d)/g, ' ')
    .replace(/(?<![\d.,])\d+(?:-\d+){2,}(?![\d.,])/g, ' ')
    // 2) Remove telefones completos COM ou SEM parênteses, DDD 2 ou 3 dígitos (011), com ou sem hífen central e +55 colado
    .replace(
      /(?:(?:\+\d{1,3}[ \t]*|\b55[ \t]+))?(?:\(0?\d{2}\)[ \t]*|\b0?\d{2}[ \t]+)\d{4,5}[-\s]?\d{4}\b/g,
      ' '
    )
    // 3) Remove CEPs simples, telefones curtos e contas hifenizadas ("01310-100", "98888-7777", "56789-0")
    .replace(/(?<![\d.,/-])\d+-\d+(?![\d.,/-])/g, ' ')
    .replace(/\b\d{8,}\b/g, ' ')
    .replace(/\b\d{1,2}:\d{2}\b/g, ' ')
    .replace(/\b\d{1,2}h(?:\d{2})?\b/gi, ' ');

  // Rejeita valores negativos explícitos, vírgulas malformadas com 3+ dígitos ("150,555", "1,500") e centavos decimais ("10,50 centavos")
  if (
    /r\$[ \t]*-[ \t]*\d/i.test(withoutContactsAndDates) ||
    /-[ \t]*r\$[ \t]*\d/i.test(withoutContactsAndDates) ||
    /(?:^|[\s(/:=])-\d/.test(withoutContactsAndDates) ||
    /\d,\d{3,}/.test(withoutContactsAndDates) ||
    /\d[.,]\d+[ \t]*centavos?\b/i.test(withoutContactsAndDates)
  ) {
    return null;
  }

  // Rejeita expressões de soma/multiplicação ("R$ 50 + 30") e dúvidas sobre taxas/descontos
  if (
    /\d[ \t]*[+*][ \t]*(?:r\$[ \t]*)?\d/i.test(withoutContactsAndDates) ||
    /\b(?:tem[ \t]+|qual[ \t]+(?:a[ \t]+)?|cobra[ \t]+)?(?:taxa|tarifa|juros|multa|desconto)[ \t]+d[eo][ \t]+(?:r\$[ \t]*)?\d/i.test(
      withoutContactsAndDates
    )
  ) {
    return null;
  }

  // Rejeita porcentagens
  const pctRegex = new RegExp(
    `${NUM_LEFT}(?:${NUM_CORE})[ \\t]*(?:%|por[ \\t]*cento\\b|porcento\\b)`,
    'i'
  );
  if (pctRegex.test(withoutContactsAndDates)) {
    return null;
  }

  // Rejeita multiplicadores de quantidade ("2 itens de R$ 50", "2 pix de 50", "3x de R$ 50")
  if (
    /\b\d+[ \t]*(?:itens?|unidades?|pe[cç]as?|produtos?|pacotes?|caixas?|kits?|ingressos?|cotas?|x|vezes|parcelas?)[ \t]+(?:de[ \t]+|por[ \t]+|a[ \t]+)?(?:r\$[ \t]*)?\d/i.test(
      withoutContactsAndDates
    ) ||
    /\b(?:[2-9]|\d{2,})[ \t]*pix[ \t]+(?:de[ \t]+|por[ \t]+|a[ \t]+)?(?:r\$[ \t]*)?\d/i.test(
      withoutContactsAndDates
    )
  ) {
    return null;
  }

  const sanitized = withoutContactsAndDates
    // Remove hashtags/códigos (#80, #150), dados bancários/pedidos com ou sem ':' ("ag: 1234", "pedido: 150", "id: 500")
    .replace(/#[ \t]*\d+(?:[.,]\d+)?/g, ' ')
    .replace(
      /\b(?:pedido|ordem|protocolo|chamado|fatura|boleto|nota|nf|mesa|quarto|apto|apartamento|id|cod|c[oó]digo|item|op[cç][aã]o|ag[eê]ncia|ag|conta|cc|banco|cpf|cnpj|cep|rg)(?:[ \t]*[:=-][ \t]*(?:#|n[º°o.]?[ \t:.=-]*)?|[ \t]+(?:#|n[º°o.]?[ \t:.=-]*)?|[ \t]*#[ \t]*)\d+(?:[.,]\d+)?\b/gi,
      ' '
    )
    // Converte composições faladas em português ("2 mil e 500", "um mil", "mil reais", "5 mil", "1.500 reais e 50 centavos", "150 centavos")
    .replace(/(?<![-\w@/,]|\d\.)um[ \t]+mil[ \t]+e[ \t]+(\d{1,3})(?![.,]\d|\d)/gi, (_m, rest) =>
      String(1000 + Number(rest))
    )
    .replace(
      /(?<![-\w@/,]|\d\.)(\d{1,3})[ \t]*mil[ \t]+e[ \t]+(\d{1,3})(?![.,]\d|\d)/gi,
      (_m, k, rest) => String(Number(k) * 1000 + Number(rest))
    )
    .replace(/\bum[ \t]+mil\b/gi, '1000')
    .replace(/\br\$[ \t]*mil\b/gi, 'R$ 1000')
    .replace(/\bmil[ \t]+(reais|real|brl|contos?)\b/gi, '1000 $1')
    .replace(/\bpix[ \t]+de[ \t]+mil\b/gi, 'pix de 1000')
    .replace(
      /(?<![-\w@/,]|\d\.)(\d{1,4}(?:[.,]\d{1,2})?)(?![.,]\d|\d)[ \t]*mil\b/gi,
      (_m, nStr) => {
        const val = Number(String(nStr).replace(',', '.')) * 1000;
        return Number.isFinite(val) ? String(Math.round(val * 100) / 100).replace('.', ',') : ' ';
      }
    )
    .replace(
      /(?<![-\w@/,]|\d\.)(\d{1,3}(?:\.\d{3})+|\d{1,6})[ \t]*(?:reais|real)[ \t]+e[ \t]+(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?\b/gi,
      (_m, r, c) => `R$ ${String(r).replace(/\./g, '')},${String(c).padStart(2, '0')}`
    )
    .replace(/(?<![-\w@/,]|\d\.)(\d{1,6})(?![.,]\d|\d)[ \t]*centavos?\b/gi, (_m, c) => {
      const valFixed = (Number(c) / 100).toFixed(2).replace('.', ',');
      return `R$ ${valFixed}`;
    })
    // Remove "1 pix" / "5 pix" (sem valor ou com valor já separado), parcelas ("3x") e durações ("15 min")
    .replace(/(?<!r\$[ \t]*)\b\d+[ \t]+pix\b/gi, ' pix ')
    .replace(/\b\d+[ \t]*(?:x|vezes|parcelas?)\b/gi, ' ')
    .replace(/\b\d+[ \t]*(?:min|minutos?|seg|segundos?|dias?|horas?|meses|anos?)\b/gi, ' ');

  // Rejeita somas implícitas com "e" entre dois valores distintos ("pix de R$ 50 e 30 reais")
  if (
    /(?<![-\w@/,]|\d\.)(?:r\$[ \t]*)?\d[\d.,]*[ \t]*(?:reais|real|brl|conto|contos)?[ \t]+e[ \t]+(?:r\$[ \t]*)?\d/i.test(
      sanitized
    )
  ) {
    return null;
  }

  // Extrai todos os candidatos numéricos livres com fronteiras esquerda/direita estritas
  const allTokensRegex = new RegExp(`${NUM_LEFT}(${NUM_CORE})${NUM_RIGHT}`, 'g');
  const allMatches = Array.from(sanitized.matchAll(allTokensRegex))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);

  // Rejeita dúvidas/escolhas com "ou" quando há 2 ou mais números distintos na frase
  if (
    /(?<!\d)\d+(?:[.,]\d+)?(?:[ \t]+(?:reais|real|brl|conto|contos))?[ \t]+ou[ \t]+(?:r\$[ \t]*)?\d/i.test(
      sanitized
    ) ||
    (/\bou\b/i.test(sanitized) && new Set(allMatches).size > 1)
  ) {
    return null;
  }

  // Camada 1: precedido por R$ (exige candidato único distinto)
  const explicitPrefixGlobal = new RegExp(`(?<!-)r\\$[ \\t]*(${NUM_CORE})${NUM_RIGHT}`, 'gi');
  const prefixMatches = Array.from(sanitized.matchAll(explicitPrefixGlobal))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);
  const uniquePrefix = Array.from(new Set(prefixMatches));
  if (uniquePrefix.length > 1) return null;
  if (uniquePrefix.length === 1) return uniquePrefix[0];

  // Camada 2: seguido por reais / real / brl / conto (exige candidato único distinto)
  const explicitSuffixGlobal = new RegExp(
    `${NUM_LEFT}(${NUM_CORE})[ \\t]*(?:reais|real|brl|conto|contos)\\b`,
    'gi'
  );
  const suffixMatches = Array.from(sanitized.matchAll(explicitSuffixGlobal))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);
  const uniqueSuffix = Array.from(new Set(suffixMatches));
  if (uniqueSuffix.length > 1) return null;
  if (uniqueSuffix.length === 1) return uniqueSuffix[0];

  // Camada 3: único número candidato inequívoco na frase
  if (allMatches.length !== 1) return null;

  return allMatches[0];
}

/**
 * Varredura linear O(N) com dois ponteiros — zero regex backtracking!
 */
export function normalizeCommandText(text: string): string {
  if (typeof text !== 'string' || text.length > MAX_COMMAND_LEN) return '';
  let start = 0;
  let end = text.length - 1;

  while (start <= end && EDGE_PUNCT_CHARS.has(text[start])) {
    start++;
  }
  while (end >= start && EDGE_PUNCT_CHARS.has(text[end])) {
    end--;
  }
  if (start > end) return '';

  return text
    .slice(start, end + 1)
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

export function isExitCommand(text: string): boolean {
  const n = normalizeCommandText(text);
  if (!n) return false;
  return /^(?:sair|encerrar|encerrar atendimento|finalizar atendimento|parar)$/.test(n);
}

export function isCancelCommand(text: string): boolean {
  const n = normalizeCommandText(text);
  if (!n) return false;
  if (
    /^(?:cancelar|cancela|reiniciar|reinicia|reset|resetar)(?: (?:o |a |esse |essa |meu |minha )?(?:pix|cobran[cç]a|pedido|tudo|atendimento|agora))?$/.test(
      n
    )
  ) {
    return true;
  }
  return /^(?:quero|pode|favor|por favor|preciso) (?:cancelar|reiniciar)(?: (?:o |a |esse |essa |meu |minha )?(?:pix|cobran[cç]a|pedido|tudo|atendimento|agora))?$/.test(
    n
  );
}

export function isHelpCommand(text: string): boolean {
  const n = normalizeCommandText(text);
  if (!n) return false;
  return (
    /^(?:ajuda|help|menu|op[cç][oõ]es|instru[cç][oõ]es|comandos)$/.test(n) ||
    /\b(?:como (?:funciona|fa[cç]o para pagar|pagar no pix|usar)|preciso de ajuda|me ajuda)\b/i.test(
      n
    )
  );
}

export interface ActiveMenuParseResult {
  choice: 'resend' | 'new' | 'none';
  explicitOptionDigit: '1' | '2' | null;
  inlineNewAmountBrl: number | null;
}

/**
 * Interpreta respostas ao menu `1 / 2` de cobrança ativa em tempo O(N), tratando `"2."`, `"quero a 2"`,
 * `"manda de novo"` (= reenviar!) e `"cancela e gera de 100"` (= novo!).
 */
export function parseActiveOrderMenuReply(text: string): ActiveMenuParseResult {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) {
    return { choice: 'none', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  const strippedMd = text.replace(/[*_~`]/g, '').trim();
  if (!strippedMd) {
    return { choice: 'none', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  // Passo 1: Opção explícita 1 ou 2 ("1", "2.", "2)", "(2)", "#2", "opção 2", "quero a 2", "quero a opção 2", "2 - gerar 80")
  const leadingOptMatch = strippedMd.match(
    /^(?:(?:quero|escolho|prefiro|vai|fico[ \t]+com|pode[ \t]+ser)[ \t]+)?(?:(?:a|o|na|no)[ \t]+)?(?:[([]\s*)?(?:#\s*)?(?:(?:op[cç][aã]o|item|n[uú]mero)[ \t#:.-]*)?([12])(?![0-9]|[.,][0-9])(?:[)\].:,\-!?\s]+([\s\S]*))?$/i
  );
  if (leadingOptMatch) {
    const optDigit = leadingOptMatch[1] as '1' | '2';
    const remainder = (leadingOptMatch[2] ?? '').trim();
    const inlineAmt = remainder ? parseBrlAmountFromText(remainder) : null;

    if (
      remainder &&
      (/\bcancel(?:ar|a|e)\b/i.test(remainder) ||
        /\b(?:(?<!de[ \t]+)nov[oa]|outr[oa]|trocar|troca|mudar|muda|substituir|alterar)\b/i.test(
          remainder
        ))
    ) {
      return { choice: 'new', explicitOptionDigit: '2', inlineNewAmountBrl: inlineAmt };
    }

    return {
      choice: optDigit === '1' ? 'resend' : 'new',
      explicitOptionDigit: optDigit,
      inlineNewAmountBrl: optDigit === '2' ? inlineAmt : null,
    };
  }

  // Passo 2: Intenção textual de cancelar/substituir/novo valor (excluindo a locução "de novo" = novamente!)
  if (
    /\bcancel(?:ar|a|e)\b/i.test(strippedMd) ||
    /\b(?:(?<!de[ \t]+)nov[oa]|outr[oa]|trocar|troca|mudar|muda|substituir|alterar)\b/i.test(
      strippedMd
    )
  ) {
    return {
      choice: 'new',
      explicitOptionDigit: null,
      inlineNewAmountBrl: parseBrlAmountFromText(strippedMd),
    };
  }

  // Passo 3: Intenção textual de reenviar/manter cobrança existente (incluindo "manda de novo", sem negação "não")
  if (
    !/\bn[aã]o\b/i.test(strippedMd) &&
    (/\b(?:reenviar|reenvia|mesm[oa]|manter|mantenha|continua|continuar)\b/i.test(strippedMd) ||
      /\bde[ \t]+novo\b/i.test(strippedMd) ||
      /\b(?:mand[ae]|envi[ae])[ \t]+(?:a[ \t]+|o[ \t]+)?atual\b/i.test(strippedMd))
  ) {
    return { choice: 'resend', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  return {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: parseBrlAmountFromText(strippedMd),
  };
}

export function isStatusQueryMessage(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) return false;
  const n = normalizeCommandText(text);
  if (
    n &&
    /^(?:status|comprovante|meu pix|ver status|consultar|situa[cç][aã]o)(?: d[oa] (?:meu )?(?:pix|pagamento|pedido|cobran[cç]a))?$/.test(
      n
    )
  ) {
    return true;
  }

  const t = text.trim();
  if (!t) return false;

  if (
    /\b(?:quero|gera|gerar|manda|mandar|preciso|faz|fazer)[ \t]+(?:outro|novo|mais[ \t]+um)\b/i.test(
      t
    )
  ) {
    return false;
  }

  return (
    /\b(?:qual[ \t]+(?:[eé][ \t]+)?(?:o[ \t]+)?status|status[ \t]+d[oa][ \t]+(?:meu[ \t]+)?(?:pix|pagamento|cobran[cç]a|pedido))\b/i.test(
      t
    ) ||
    /\b(?:j[aá][ \t]+)?(?:confirmou|caiu|compensou|recebeu|receberam|entrou|aprovou)\b/i.test(t) ||
    /\bdeu[ \t]+certo[ \t]+(?:o[ \t]+|meu[ \t]+)?(?:pix|pagamento)\b/i.test(t)
  );
}

/**
 * Detecta mensagens/legendas pós-pagamento sem bloquear pedidos em 1ª pessoa ("Pago R$ 50", "Por R$ 50 pago agora").
 */
export function isPaymentConfirmationMessage(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) return false;
  const t = text.trim();
  if (!t) return false;

  if (
    /\b(?:quero|gera|gerar|manda|mandar|preciso|faz|fazer)[ \t]+(?:outro|novo|mais[ \t]+um)\b/i.test(
      t
    ) ||
    /\b(?:quero|preciso|vou|posso|pode|gostaria[ \t]+de)[ \t]+(?:pagar|fazer[ \t]+um[ \t]+pix|gerar)\b/i.test(
      t
    )
  ) {
    return false;
  }

  if (normalizeCommandText(t) === 'pago') {
    return true;
  }

  const isQuestion = t.endsWith('?');
  const hasConditionalOfferPrefix =
    /\b(?:eu|se|caso)[ \t]+/i.test(t) || /\bpor[ \t]+(?:r\$[ \t]*)?\d/i.test(t);

  if (
    !isQuestion &&
    !hasConditionalOfferPrefix &&
    (/^[ \t]*pago[ \t]+(?:o|meu)[ \t]+(?:pix|pagamento)\b/i.test(t) ||
      /^[ \t]*(?:feito|realizado|efetuado|enviado|transferido)[ \t]+(?:o[ \t]+|meu[ \t]+)?(?:pix|pagamento|valor|r\$[ \t]*\d)/i.test(
        t
      ) ||
      /(?:(?<!\w)r\$[ \t]*\d[\d.,]*|(?<![-\w.,])\d[\d.,]*)[ \t]*(?:reais[ \t]+)?(?:j[aá][ \t]+)?(?:foi[ \t]+|est[aá][ \t]+|t[aá][ \t]+)?pago(?![ \t]+(?:agora|hoje|amanh[aã]|depois|se\b))\b/i.test(
        t
      ))
  ) {
    return true;
  }

  return (
    /\b(?:paguei|quitei|depositei|passei)\b/i.test(t) ||
    /\bcomprovante\b/i.test(t) ||
    /\b(?:t[aá]|est[aá]|foi)[ \t]+pago\b/i.test(t) ||
    /\bpix[ \t]+(?:de[ \t]+)?(?:(?:r\$[ \t]*)?[\d.,]+[ \t]+(?:reais[ \t]+)?)?(?:j[aá][ \t]+)?(?:foi[ \t]+|est[aá][ \t]+|t[aá][ \t]+)?(?:pago|enviado|feito|realizado|efetuado|conclu[ií]do|transferido)\b/i.test(
      t
    ) ||
    /\bpagamento[ \t]+(?:d[eo][ \t]+)?(?:(?:r\$[ \t]*)?[\d.,]+[ \t]+(?:reais[ \t]+)?)?(?:j[aá][ \t]+)?(?:foi[ \t]+|est[aá][ \t]+|t[aá][ \t]+)?(?:feito|realizado|efetuado|enviado|conclu[ií]do|pago)\b/i.test(
      t
    ) ||
    /\b(?:j[aá][ \t]+)?(?:fiz|efetuei|realizei)[ \t]+(?:(?:o[ \t]+|os[ \t]+|a[ \t]+|um[ \t]+)?(?:pix|pagamento|dep[oó]sito|transfer[eê]ncia)|(?:os[ \t]+)?(?:r\$[ \t]*)?\d)/i.test(
      t
    ) ||
    /\bacabei[ \t]+de[ \t]+(?:pagar|fazer|enviar|mandar|transferir|depositar|passar)\b/i.test(t) ||
    /\b(?:mandei|enviei|transferi)[ \t]+(?:o[ \t]+|os[ \t]+|a[ \t]+|as[ \t]+|um[ \t]+|meu[ \t]+)?(?:pix|pagamento|valor|comprovante|r\$[ \t]*\d|\d)/i.test(
      t
    )
  );
}

export function formatBrl(amount: number): string {
  return amount.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

export function formatTimeSaoPaulo(isoOrDate: string | Date): string {
  const d = typeof isoOrDate === 'string' ? new Date(isoOrDate) : isoOrDate;
  return d.toLocaleTimeString('pt-BR', {
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'America/Sao_Paulo',
  });
}
