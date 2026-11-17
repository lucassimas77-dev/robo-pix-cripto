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
  '*',
  '_',
  '~',
  '`',
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
const NUM_LEFT = '(?<![-\\wÀ-ÿºª°@/,.])';
const NUM_RIGHT = '(?![.,]\\d|\\d|[-\\wÀ-ÿºª°]|[ \\t]*%|\\.[a-zA-Z]|\\/[A-Za-zÀ-ÿ0-9])';

function normalizeHorizontalSpaces(input: string): string {
  return input.replace(/[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/g, ' ');
}

const PT_UNITS: Record<string, number> = {
  um: 1,
  uma: 1,
  dois: 2,
  duas: 2,
  tres: 3,
  três: 3,
  quatro: 4,
  cinco: 5,
  seis: 6,
  sete: 7,
  oito: 8,
  nove: 9,
};

const PT_TEENS: Record<string, number> = {
  dez: 10,
  onze: 11,
  doze: 12,
  treze: 13,
  quatorze: 14,
  catorze: 14,
  quinze: 15,
  dezesseis: 16,
  dezessete: 17,
  dezoito: 18,
  dezenove: 19,
};

const PT_TENS: Record<string, number> = {
  vinte: 20,
  trinta: 30,
  quarenta: 40,
  cinquenta: 50,
  sessenta: 60,
  setenta: 70,
  oitenta: 80,
  noventa: 90,
};

const PT_HUNDREDS: Record<string, number> = {
  duzentos: 200,
  duzentas: 200,
  trezentos: 300,
  trezentas: 300,
  quatrocentos: 400,
  quatrocentas: 400,
  quinhentos: 500,
  quinhentas: 500,
  seiscentos: 600,
  seiscentas: 600,
  setecentos: 700,
  setecentas: 700,
  oitocentos: 800,
  oitocentas: 800,
  novecentos: 900,
  novecentas: 900,
};

const CURRENCY_OR_SCALE_WORDS = new Set([
  'mil',
  'milhao',
  'milhão',
  'milhoes',
  'milhões',
  'real',
  'reais',
  'brl',
  'conto',
  'contos',
  'centavo',
  'centavos',
]);

const QTY_OR_UNIT_WORDS = new Set([
  'pix',
  'item',
  'itens',
  'unidade',
  'unidades',
  'peca',
  'peça',
  'pecas',
  'peças',
  'produto',
  'produtos',
  'pacote',
  'pacotes',
  'caixa',
  'caixas',
  'kit',
  'kits',
  'ingresso',
  'ingressos',
  'cota',
  'cotas',
  'x',
  'vezes',
  'parcela',
  'parcelas',
  'min',
  'minuto',
  'minutos',
  'seg',
  'segundo',
  'segundos',
  'hora',
  'horas',
  'dia',
  'dias',
  'semana',
  'semanas',
  'mes',
  'mês',
  'meses',
  'ano',
  'anos',
]);

function readSubHundredTokens(
  tokens: string[],
  idx: number
): { value: number; endIdx: number; singleUm: boolean } | null {
  if (idx >= tokens.length) return null;
  const w = tokens[idx].toLowerCase();
  if (w in PT_TEENS) {
    return { value: PT_TEENS[w], endIdx: idx, singleUm: false };
  }
  if (w in PT_TENS) {
    const base = PT_TENS[w];
    if (
      idx + 4 < tokens.length &&
      /^[ \t]+$/.test(tokens[idx + 1]) &&
      tokens[idx + 2].toLowerCase() === 'e' &&
      /^[ \t]+$/.test(tokens[idx + 3])
    ) {
      const u = tokens[idx + 4].toLowerCase();
      if (u in PT_UNITS) {
        return { value: base + PT_UNITS[u], endIdx: idx + 4, singleUm: false };
      }
    }
    return { value: base, endIdx: idx, singleUm: false };
  }
  if (w in PT_UNITS) {
    return { value: PT_UNITS[w], endIdx: idx, singleUm: w === 'um' || w === 'uma' };
  }
  return null;
}

function readSubThousandTokens(
  tokens: string[],
  idx: number
): { value: number; endIdx: number; singleUm: boolean } | null {
  if (idx >= tokens.length) return null;
  const w = tokens[idx].toLowerCase();
  if (w === 'cem') {
    return { value: 100, endIdx: idx, singleUm: false };
  }
  if (w === 'cento') {
    if (
      idx + 4 < tokens.length &&
      /^[ \t]+$/.test(tokens[idx + 1]) &&
      tokens[idx + 2].toLowerCase() === 'e' &&
      /^[ \t]+$/.test(tokens[idx + 3])
    ) {
      const sub = readSubHundredTokens(tokens, idx + 4);
      if (sub) {
        return { value: 100 + sub.value, endIdx: sub.endIdx, singleUm: false };
      }
    }
    return null;
  }
  if (w in PT_HUNDREDS) {
    const base = PT_HUNDREDS[w];
    if (
      idx + 4 < tokens.length &&
      /^[ \t]+$/.test(tokens[idx + 1]) &&
      tokens[idx + 2].toLowerCase() === 'e' &&
      /^[ \t]+$/.test(tokens[idx + 3])
    ) {
      const sub = readSubHundredTokens(tokens, idx + 4);
      if (sub) {
        return { value: base + sub.value, endIdx: sub.endIdx, singleUm: false };
      }
    }
    return { value: base, endIdx: idx, singleUm: false };
  }
  return readSubHundredTokens(tokens, idx);
}

/**
 * Converte numerais cardinais por extenso em português (`2..999` e `um` antes de escala/moeda)
 * em passe único linear O(N), sem falsos positivos em horários coloquiais ("às cinco", "nós dois").
 */
function normalizePortugueseNumberWords(input: string): string {
  const tokens = input.match(/[A-Za-zÀ-ÿ]+|\d+(?:[.,]\d+)?|[^A-Za-zÀ-ÿ\d]+/g);
  if (!tokens || tokens.length === 0) return input;

  const wordIndices: number[] = [];
  for (let k = 0; k < tokens.length; k++) {
    if (/^[A-Za-zÀ-ÿ]+$/.test(tokens[k])) {
      wordIndices.push(k);
    }
  }
  const wordPosMap = new Map<number, number>();
  for (let p = 0; p < wordIndices.length; p++) {
    wordPosMap.set(wordIndices[p], p);
  }

  const out: string[] = [];
  let i = 0;
  while (i < tokens.length) {
    if (!/^[A-Za-zÀ-ÿ]+$/.test(tokens[i])) {
      out.push(tokens[i]);
      i++;
      continue;
    }

    const parsed = readSubThousandTokens(tokens, i);
    if (!parsed) {
      out.push(tokens[i]);
      i++;
      continue;
    }

    const { value, endIdx, singleUm } = parsed;
    const prevSep = i > 0 ? tokens[i - 1] : '';
    const nextSep = endIdx + 1 < tokens.length ? tokens[endIdx + 1] : '';
    if (/[-/@.]/.test(prevSep) || /^[-/@.]/.test(nextSep)) {
      out.push(tokens[i]);
      i++;
      continue;
    }

    const startWordPos = wordPosMap.get(i) ?? -1;
    const endWordPos = wordPosMap.get(endIdx) ?? -1;
    const prevWord =
      startWordPos > 0 && i - wordIndices[startWordPos - 1] <= 2
        ? tokens[wordIndices[startWordPos - 1]].toLowerCase()
        : '';
    const prevPrevWord =
      startWordPos > 1 && wordIndices[startWordPos - 1] - wordIndices[startWordPos - 2] <= 2
        ? tokens[wordIndices[startWordPos - 2]].toLowerCase()
        : '';
    const nextWord =
      endWordPos >= 0 &&
      endWordPos + 1 < wordIndices.length &&
      wordIndices[endWordPos + 1] - endIdx <= 2
        ? tokens[wordIndices[endWordPos + 1]].toLowerCase()
        : '';

    const blockedPronounOrHour =
      !CURRENCY_OR_SCALE_WORDS.has(nextWord) &&
      !QTY_OR_UNIT_WORDS.has(nextWord) &&
      (['as', 'às', 'pelas', 'das', 'nos', 'nós', 'voces', 'vocês', 'eles', 'elas', 'ambos', 'ambas', 'uns', 'umas'].includes(
        prevWord
      ) ||
        (prevWord === 'os' && value === 2));

    // Centavos coloquiais por extenso: "dez e cinquenta" -> "10,50", "vinte e cinco e cinquenta" -> "25,50"
    if (
      !blockedPronounOrHour &&
      prevWord !== 'entre' &&
      endIdx + 4 < tokens.length &&
      /^[ \t]+$/.test(tokens[endIdx + 1]) &&
      tokens[endIdx + 2].toLowerCase() === 'e' &&
      /^[ \t]+$/.test(tokens[endIdx + 3]) &&
      /^[A-Za-zÀ-ÿ]+$/.test(tokens[endIdx + 4])
    ) {
      const centsSub = readSubHundredTokens(tokens, endIdx + 4);
      if (centsSub) {
        const afterCentsSep =
          centsSub.endIdx + 1 < tokens.length ? tokens[centsSub.endIdx + 1] : '';
        const centsEndWordPos = wordPosMap.get(centsSub.endIdx) ?? -1;
        const wordAfterCents =
          centsEndWordPos >= 0 &&
          centsEndWordPos + 1 < wordIndices.length &&
          wordIndices[centsEndWordPos + 1] - centsSub.endIdx <= 2
            ? tokens[wordIndices[centsEndWordPos + 1]].toLowerCase()
            : '';
        const blockedCentsNext = ['mil', 'milhao', 'milhão', 'milhoes', 'milhões'].includes(
          wordAfterCents
        );
        if (
          !blockedCentsNext &&
          !/^[-/@.]/.test(afterCentsSep) &&
          (!centsSub.singleUm || wordAfterCents === 'centavo' || wordAfterCents === 'centavos')
        ) {
          const formattedDec = `${value},${String(centsSub.value).padStart(2, '0')}`;
          if (wordAfterCents === 'centavo' || wordAfterCents === 'centavos') {
            out.push(`${formattedDec} reais`);
            i = wordIndices[centsEndWordPos + 1] + 1;
          } else {
            out.push(formattedDec);
            i = centsSub.endIdx + 1;
          }
          continue;
        }
      }
    }

    let shouldConvert = false;
    if (singleUm) {
      shouldConvert =
        CURRENCY_OR_SCALE_WORDS.has(nextWord) ||
        (prevWord === 'e' && prevPrevWord === 'mil');
    } else {
      shouldConvert = !blockedPronounOrHour;
    }

    if (shouldConvert) {
      out.push(String(value));
      i = endIdx + 1;
    } else {
      out.push(tokens[i]);
      i++;
    }
  }

  return out.join('');
}

function unwrapWhatsAppMarkdown(input: string): string {
  let s = input;
  for (let pass = 0; pass < 2; pass++) {
    s = s
      .replace(/(^|[\s([{"'])\*([^*\n]+)\*(?=$|[\s)\]}"'.,!?;:])/g, (m, lead, inner) =>
        /^\s|\s$/.test(inner) ? m : `${lead}${inner}`
      )
      .replace(/(^|[\s([{"'])_([^_\n]+)_(?=$|[\s)\]}"'.,!?;:])/g, (m, lead, inner) =>
        /^\s|\s$/.test(inner) ? m : `${lead}${inner}`
      )
      .replace(/(^|[\s([{"'])~([^~\n]+)~(?=$|[\s)\]}"'.,!?;:])/g, (m, lead, inner) =>
        /^\s|\s$/.test(inner) ? m : `${lead}${inner}`
      )
      .replace(/(^|[\s([{"'])`([^`\n]+)`(?=$|[\s)\]}"'.,!?;:])/g, '$1$2');
  }
  return s;
}

export function hasPixTriggerKeyword(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) return false;
  return /(?<![A-Za-zÀ-ÿ0-9])(?:pix|pagar|pagamento|comprovante)(?![A-Za-zÀ-ÿ0-9])/i.test(
    normalizeHorizontalSpaces(text)
  );
}

export function parseBrlAmountFromText(text: string): number | null {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) return null;
  const cleaned = normalizeHorizontalSpaces(text).trim();
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

  // Rejeita multiplicação/soma compacta ANTES de desenrolar formatação Markdown ("2*50", "2 * 3 * 50")
  if (/\d[ \t]*[+*×÷][ \t]*(?:r\$[ \t]*)?\d/i.test(filteredWords)) {
    return null;
  }

  // Remove formatação Markdown pareada do WhatsApp (*50,00*, _50,00_, ~50~, `50`) sem fundir "2*50" nem tocar em ord_123
  const unformattedWords = unwrapWhatsAppMarkdown(filteredWords);

  const withoutContactsAndDates = unformattedWords
    // 1) Remove documentos estruturados (CPF, CNPJ numérico ou alfanumérico, CEP pontuado, RG) e datas ANTES de pares hifenizados!
    .replace(/(?<![A-Za-z0-9])[A-Za-z0-9]{2}\.[A-Za-z0-9]{3}\.[A-Za-z0-9]{3}\/[A-Za-z0-9]{4}-\d{2}(?!\d)/g, ' ')
    .replace(/(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)/g, ' ')
    .replace(/(?<!\d)\d{2}\.\d{3}-\d{3}(?!\d)/g, ' ')
    .replace(/(?<!\d)\d{1,2}\.\d{3}\.\d{3}-[\dxX]\b/g, ' ')
    .replace(/(?<!\d)(?:\d{4}\/\d{1,2}\/\d{1,2}|\d{1,2}\/\d{1,2}(?:\/\d{2,4})?)(?!\d)/g, ' ')
    .replace(/(?<!\d)(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}-\d{1,2}-\d{2,4})(?!\d)/g, ' ')
    .replace(/(?<![\d.,])\d+(?:-\d+){2,}(?![\d.,])/g, ' ')
    // 2) Remove telefones completos COM ou SEM parênteses, DDD 2 ou 3 dígitos (011), com ou sem espaço após DDD/DDI
    .replace(
      /(?:(?:\+\d{1,3}[ \t]*|\b55[ \t]+))?(?:\(0?\d{2}\)[ \t]*|\b0?\d{2}[ \t]*)\d{4,5}[-\s]?\d{4}\b/g,
      ' '
    )
    // 3) Remove CEPs simples, telefones curtos, números longos e horários HH:MM(:SS)(h/min) ou 10h(30min)
    .replace(/(?<![\d.,/-])\d+-\d+(?![\d.,/-])/g, ' ')
    .replace(/\b\d{8,}\b/g, ' ')
    .replace(
      /\b\d{1,2}:\d{2}(?::\d{2})?(?:[ \t]*(?:h|hs|hr|hrs|horas?|min|mins|minutos?))?(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    .replace(
      /\b\d{1,2}[ \t]*(?:h|hs|hr|hrs)(?:\d{2}(?:[ \t]*min(?:utos?)?)?)?(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    );

  // Converte numerais cardinais em português ("dois mil", "dez e cinquenta", "quatro da tarde") ANTES de limpar horas/dias!
  const withNormalizedPtNumbers = normalizePortugueseNumberWords(withoutContactsAndDates)
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])(?:[aà]s|pelas|das)[ \t]+(?:[01]?\d|2[0-4])\b(?![.,]\d|[ \t]*(?:reais|real|brl|contos?|centavos?)\b)(?:[ \t]+da[ \t]+(?:manh[aã]|tarde|noite|madrugada)(?![A-Za-zÀ-ÿ0-9]))?/gi,
      ' '
    )
    .replace(
      /\b(?:[01]?\d|2[0-4])[ \t]+da[ \t]+(?:manh[aã]|tarde|noite|madrugada)(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    .replace(
      /(?<!\bbom[ \t]+)\bdia[ \t]+(?:[0-2]?\d|3[01])\b(?![.,]\d|[ \t]*(?:reais|real|brl|contos?|centavos?)\b)/gi,
      ' '
    );

  // Rejeita valores negativos explícitos, vírgulas malformadas ("150,555", "1,500"), centavos decimais e quantificadores vagos antes de "mil"
  if (
    /r\$[ \t]*-[ \t]*\d/i.test(withNormalizedPtNumbers) ||
    /-[ \t]*r\$[ \t]*\d/i.test(withNormalizedPtNumbers) ||
    /(?:^|[\s(/:=])-\d/.test(withNormalizedPtNumbers) ||
    /\d,\d{3,}/.test(withNormalizedPtNumbers) ||
    /\d[.,]\d+[ \t]*centavos?\b/i.test(withNormalizedPtNumbers) ||
    /\b(?:quantos?|v[aá]rios?|alguns|algumas|muitos?|poucos?|tantos?|uns|umas)[ \t]+mil\b/i.test(
      withNormalizedPtNumbers
    )
  ) {
    return null;
  }

  // Rejeita expressões aritméticas (+, *, /, dividido, -, menos) e dúvidas sobre taxas/descontos (inclusive "taxa no pix de 100")
  if (
    /\d[ \t]*[+*×÷/][ \t]*(?:r\$[ \t]*)?\d/i.test(withNormalizedPtNumbers) ||
    /\bdividid[oa]s?[ \t]+(?:por|em)[ \t]+\d/i.test(withNormalizedPtNumbers) ||
    /(?<![-\w@/,.])(?:r\$[ \t]*)?\d[\d.,]*[ \t]*(?:reais|real|brl|contos?)?(?:[ \t]*-[ \t]*(?:r\$[ \t]*)?\d|[ \t]+menos[ \t]+(?:r\$[ \t]*)?\d)/i.test(
      withNormalizedPtNumbers
    ) ||
    /\b(?:taxa|tarifa|juros|multa|desconto)(?:[ \t]+(?:de|do|da|no|na|em|num|numa|pra|para|pro|sobre|acima|abaixo|por|o|a|um|uma|pix|pagamento|cobran[cç]a|valor)){1,6}[ \t]+(?:r\$[ \t]*)?\d/i.test(
      withNormalizedPtNumbers
    )
  ) {
    return null;
  }

  // Rejeita porcentagens
  const pctRegex = new RegExp(
    `${NUM_LEFT}(?:${NUM_CORE})[ \\t]*(?:%|por[ \\t]*cento\\b|porcento\\b)`,
    'i'
  );
  if (pctRegex.test(withNormalizedPtNumbers)) {
    return null;
  }

  // Rejeita multiplicadores de quantidade ("2 itens de R$ 50", "2 pix de 50", "3x de R$ 50")
  if (
    /\b\d+[ \t]*(?:itens?|unidades?|pe[cç]as?|produtos?|pacotes?|caixas?|kits?|ingressos?|cotas?|x|vezes|parcelas?)[ \t]+(?:de[ \t]+|por[ \t]+|a[ \t]+)?(?:r\$[ \t]*)?\d/i.test(
      withNormalizedPtNumbers
    ) ||
    /\b(?:[2-9]|\d{2,})[ \t]*pix[ \t]+(?:de[ \t]+|por[ \t]+|a[ \t]+)?(?:r\$[ \t]*)?\d/i.test(
      withNormalizedPtNumbers
    )
  ) {
    return null;
  }

  const sanitized = withNormalizedPtNumbers
    // Remove hashtags/códigos (#80, #150), "nº 50"/"número 50" autônomo e dados bancários/pedidos com ou sem ':'
    .replace(/#[ \t]*\d+(?:[.,]\d+)?/g, ' ')
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])(?:n[º°]|n[uú]mero|n[uú]m\.?)[ \t#:.-]*\d+(?:[.,]\d+)?(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    .replace(
      /\b(?:pedido|ordem|protocolo|chamado|fatura|boleto|nota|nf|mesa|quarto|apto|apartamento|id|cod|c[oó]digo|item|op[cç][aã]o|ag[eê]ncia|ag|conta|cc|banco|cpf|cnpj|cep|rg)(?:[ \t]*[:=-][ \t]*(?:#|n[º°o.]?[ \t:.=-]*)?|[ \t]+(?:#|n[º°o.]?[ \t:.=-]*)?|[ \t]*#[ \t]*)\d+(?:[.,]\d+)?\b/gi,
      ' '
    )
    // Remove "1 pix" / "5 pix" ANTES de normalizar "mil" para que "um pix de mil e 500" vire "pix de mil e 500" limpo!
    .replace(/(?<!r\$[ \t]*)\b\d+[ \t]+pix\b/gi, ' pix ')
    // Converte milhões para escala exata (caindo no aviso de teto máximo em vez de cobrar R$ 1,00!)
    .replace(
      /(?:(?<![-\w@/,.])(\d{1,3}(?:[.,]\d{1,2})?)(?![.,]\d|\d)[ \t]*|\b(meio)[ \t]+)milh(?:[aã]o|[oõ]es)\b/gi,
      (_m, nStr, halfWord) => {
        const mult = halfWord ? 0.5 : Number(String(nStr).replace(',', '.'));
        return String(Math.round(mult * 1_000_000));
      }
    )
    // Passagem única determinística para TODAS as composições com "mil":
    // Aceita tanto "[N] mil e M" quanto gramática padrão sem "e" / com vírgula para centenas ("[N] mil 250", "dois mil, quinhentos")!
    .replace(
      /(?:(?<![-\wÀ-ÿºª°@/,.])(\d{1,4}(?:[.,]\d{1,2})?)(?![.,]\d|\d)[ \t]*|(?<=^|[ \t]*[:=(\-,;.!?][ \t]*|r\$[ \t]*|(?<![A-Za-zÀ-ÿ0-9])(?:de|por|para|pra|no|em|gera|gerar|mand[ae]|mandar|faz|fa[cç]a|fazer|quero|preciso|pagar|cobran[cç]a|pix|valor|total|ser|[eé]|s[aã]o|oi|ol[aá]|a[ií]|ent[aã]o)[ \t]+))mil\b(?:[ \t]+(reais|real|brl|contos?)\b(?:[ \t]+e[ \t]+(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?\b)?|(?:[ \t]+e[ \t]+(?:(meio)\b|(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?\b|(\d{1,3})(?![.,]\d|\d|[ \t]*centavos?\b)(?:[ \t]*(reais|real|brl|contos?)\b)?(?:[ \t]+e[ \t]+(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?\b)?)|(?:[ \t]*,[ \t]*|[ \t]+)(?:(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?\b|([1-9]\d{2})(?![.,]\d|\d|[ \t]*centavos?\b)(?:[ \t]*(reais|real|brl|contos?)\b)?(?:[ \t]+e[ \t]+(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?\b)?))?)/gi,
      (
        _m,
        multStr,
        unit1,
        unit1Cents,
        halfWord,
        eDirectCents,
        eExtraReais,
        eUnit2,
        eTailCents,
        bareDirectCents,
        bareHundredsReais,
        bareUnit2,
        bareTailCents
      ) => {
        const mult = multStr ? Number(String(multStr).replace(',', '.')) : 1;
        if (!Number.isFinite(mult) || mult <= 0) return ' ';
        const extraStr = eExtraReais ?? bareHundredsReais;
        const addReais = halfWord ? 500 : extraStr ? Number(extraStr) : 0;
        const centsStr =
          unit1Cents ?? eDirectCents ?? eTailCents ?? bareDirectCents ?? bareTailCents;
        const cents = centsStr ? Number(centsStr) : 0;
        const total = Math.round((mult * 1000 + addReais + cents / 100) * 100) / 100;
        const formatted = Number.isInteger(total)
          ? String(total)
          : total.toFixed(2).replace('.', ',');
        const hasUnit = Boolean(unit1 || eUnit2 || bareUnit2 || centsStr);
        return hasUnit ? `${formatted} reais` : formatted;
      }
    )
    // Converte "X reais e Y [centavos]" (ex: "1.500 reais e 50 centavos", "20 reais e 50") e "N centavos" isolado
    .replace(
      /(?<![-\wÀ-ÿºª°@/,.])(\d{1,3}(?:\.\d{3})+|\d{1,6})[ \t]*(?:reais|real)[ \t]+e[ \t]+(?!r\$)(\d{1,2})(?![.,]\d|\d|[ \t]*(?:reais|real|brl|contos?|mil|milh))(?![A-Za-zÀ-ÿ0-9])(?:[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9]))?/gi,
      (_m, r, c) => `R$ ${String(r).replace(/\./g, '')},${String(c).padStart(2, '0')}`
    )
    .replace(/(?<![-\w@/,.])(\d{1,6})(?![.,]\d|\d)[ \t]*centavos?\b/gi, (_m, c) => {
      const valFixed = (Number(c) / 100).toFixed(2).replace('.', ',');
      return `R$ ${valFixed}`;
    })
    .replace(/\b\d+[ \t]*(?:x|vezes|parcelas?)\b/gi, ' ')
    .replace(
      /\b\d+[ \t]*(?:min|mins|minutos?|seg|segs|segundos?|dias?|semanas?|horas?|m[eê]s|meses|anos?)(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    );

  // Rejeita somas, subtrações e intervalos ("R$ 50 e 30", "R$ 50 mais 30", "R$ 50 - 10", "50 a 100 reais", "de 50 até 100")
  if (
    /(?<![-\w@/,.])(?:r\$[ \t]*)?\d[\d.,]*[ \t]*(?:reais|real|brl|conto|contos)?[ \t]+(?:e|mais|menos|a|à|at[eé])[ \t]+(?:r\$[ \t]*)?\d/i.test(
      sanitized
    ) ||
    /(?<![-\w@/,.])(?:r\$[ \t]*)?\d[\d.,]*[ \t]*(?:reais|real|brl|conto|contos)?[ \t]*-[ \t]*(?:r\$[ \t]*)?\d/i.test(
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

  // Qualquer segundo número distinto remanescente na frase após limpar datas/horários/contatos/documentos
  // ("Vou levar 3 de R$ 50", "Pix de R$ 50, ops 80", "Era R$ 50 mas agora é 80") representa ambiguidade real!
  const uniqueCandidates = Array.from(new Set(allMatches));
  if (uniqueCandidates.length !== 1) {
    return null;
  }

  return uniqueCandidates[0];
}

/**
 * Varredura linear O(N) com dois ponteiros — zero regex backtracking!
 */
export function normalizeCommandText(text: string): string {
  if (typeof text !== 'string' || text.length > MAX_COMMAND_LEN) return '';
  const norm = normalizeHorizontalSpaces(text);
  let start = 0;
  let end = norm.length - 1;

  while (start <= end && EDGE_PUNCT_CHARS.has(norm[start])) {
    start++;
  }
  while (end >= start && EDGE_PUNCT_CHARS.has(norm[end])) {
    end--;
  }
  if (start > end) return '';

  return norm
    .slice(start, end + 1)
    .replace(/[*_~`]/g, '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
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

const LEADING_MENU_OPT_RE =
  /^(?:(?:quero|escolho|prefiro|vai|fico[ \t]+com|pode[ \t]+ser)[ \t]+)?(?:(?:a|o|na|no)[ \t]+)?([([#][ \t]*)?(?:(op[cç][aã]o|item|n[uú]mero)[ \t#:.-]*)?([12])(?![0-9]|[.,*][0-9])(?:([ \t]*[)\].:\-!?]+[ \t]*|[ \t,]+)([\s\S]*))?$/i;

function matchLeadingMenuOption(strippedMd: string): {
  optDigit: '1' | '2';
  remainder: string;
} | null {
  const leadingOptMatch = strippedMd.match(LEADING_MENU_OPT_RE);
  if (!leadingOptMatch) return null;

  const openSym = leadingOptMatch[1] ?? '';
  const menuWord = leadingOptMatch[2] ?? '';
  const optDigit = leadingOptMatch[3] as '1' | '2';
  const sep = leadingOptMatch[4] ?? '';
  const remainder = (leadingOptMatch[5] ?? '').trim();

  const startsWithNumberUnit =
    !menuWord &&
    remainder.length > 0 &&
    /^(?:mil|milh[aã]o|milh[oõ]es|reais|real|brl|contos?|pilas?|centavos?|pix|e|ou|mais|menos|a|at[eé]|x|vezes|itens?|unidades?|parcelas?|min|minutos?|horas?|dias?|semanas?|m[eê]s|meses)(?![A-Za-zÀ-ÿ0-9])|^%/i.test(
      remainder
    );

  const hasExplicitBullet = Boolean(menuWord || openSym || /[)\].:\-!?]/.test(sep));
  const allowedBareRemainder =
    remainder.length === 0 ||
    hasExplicitBullet ||
    /^(?:r\$|(?:por[ \t]+favor|pfv?|obrigad[oa]|valeu|agrade[cç]o|agora|a[ií]|quero|preciso|mand[ae]|mandar|envi[ae]|enviar|pode|escolho|prefiro|vai|sim|ok|beleza|blz|fechado|isso|reenvi\w*|manter|mantenha|continu\w*|cancel\w*|gerar|gera|fazer|faz|nov[oa]|outr[oa]|trocar|troca|mudar|muda|substituir|alterar)(?![A-Za-zÀ-ÿ0-9]))/i.test(
      remainder
    );

  if (startsWithNumberUnit || !allowedBareRemainder) {
    return null;
  }

  return { optDigit, remainder };
}

/**
 * Retorna `true` se o cliente incluiu dígitos extras na resposta ao menu `1 / 2` além do próprio dígito da opção
 * (usado por `ConversationEngine` para evitar reaproveitar `pendingNewAmountBrl` em entradas ambíguas como `"2 - 50 ou 100"`).
 */
export function hasUnparsedDigitsInMenuReply(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) return false;
  const strippedMd = unwrapWhatsAppMarkdown(normalizeHorizontalSpaces(text)).trim();
  if (!strippedMd) return false;

  const opt = matchLeadingMenuOption(strippedMd);
  const bodyToInspect = opt ? opt.remainder : strippedMd;
  if (!bodyToInspect) return false;

  const normalizedBody = normalizePortugueseNumberWords(bodyToInspect);
  return /\d/.test(normalizedBody);
}

/**
 * Interpreta respostas ao menu `1 / 2` de cobrança ativa em tempo O(N), tratando `"2."`, `"quero a 2"`,
 * `"Quero a (2)"`, `"manda de novo"` (= reenviar!) e `"cancela e gera de 100"` (= novo!).
 */
export function parseActiveOrderMenuReply(text: string): ActiveMenuParseResult {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) {
    return { choice: 'none', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  const strippedMd = unwrapWhatsAppMarkdown(normalizeHorizontalSpaces(text)).trim();
  if (!strippedMd) {
    return { choice: 'none', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  // Passo 1: Opção explícita 1 ou 2 ("1", "2.", "2)", "(2)", "#2", "Quero a (2)", "opção 2", "2 - gerar 80")
  const matchedOpt = matchLeadingMenuOption(strippedMd);
  if (matchedOpt) {
    const { optDigit, remainder } = matchedOpt;
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

const EXPLICIT_NEW_ORDER_INTENT_RE =
  /\b(?:quero|gera|gerar|mand[ae]|mandar|preciso|faz|fazer|cria|criar)[ \t]+(?:outro|novo|mais[ \t]+um|(?:um[ \t]+)?pix[ \t]+de[ \t]+(?:r\$[ \t]*)?\d[\d.,]*|(?:uma[ \t]+)?cobran[cç]a(?![A-Za-zÀ-ÿ0-9]))/i;

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

  const rawTrimmed = unwrapWhatsAppMarkdown(normalizeHorizontalSpaces(text)).trim();
  if (!rawTrimmed) return false;
  const t = normalizePortugueseNumberWords(rawTrimmed);

  if (
    EXPLICIT_NEW_ORDER_INTENT_RE.test(t) ||
    /\b(?:quero|preciso|vou|posso|pode|gostaria[ \t]+de)[ \t]+(?:pagar|fazer[ \t]+um[ \t]+pix|gerar)\b/i.test(
      t
    )
  ) {
    return false;
  }

  return (
    /\b(?:qual[ \t]+(?:[eé][ \t]+)?(?:o[ \t]+)?status|status[ \t]+d[oa][ \t]+(?:meu[ \t]+)?(?:pix|pagamento|cobran[cç]a|pedido))\b/i.test(
      t
    ) ||
    /\b(?:j[aá][ \t]+)?(?:confirmou|caiu|compensou|recebeu|receberam|entrou|aprovou|chegou|bateu|creditou|processou)\b/i.test(
      t
    ) ||
    /\bdeu[ \t]+(?:tudo[ \t]+)?certo\b/i.test(t) ||
    /\b(?:foi|est[aá]|t[aá])[ \t]+(?:confirmad[oa]|aprovad[oa]|compensad[oa]|recebid[oa]|processad[oa]|creditad[oa]|identificad[oa])\b/i.test(
      t
    )
  );
}

/**
 * Detecta mensagens/legendas pós-pagamento sem bloquear pedidos em 1ª pessoa ("Pago R$ 50", "Por R$ 50 pago agora")
 * nem negações ("Não paguei o pix de 50 ainda", "Paguei não").
 */
export function isPaymentConfirmationMessage(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) return false;
  const rawTrimmed = unwrapWhatsAppMarkdown(normalizeHorizontalSpaces(text)).trim();
  if (!rawTrimmed) return false;

  const t = normalizePortugueseNumberWords(rawTrimmed);

  if (
    EXPLICIT_NEW_ORDER_INTENT_RE.test(t) ||
    /\b(?:quero|preciso|vou|posso|pode|gostaria[ \t]+de)[ \t]+(?:pagar|fazer[ \t]+um[ \t]+pix|gerar)\b/i.test(
      t
    ) ||
    /(?:^|[ \t,;:.!?])(?:ainda[ \t]+)?n[aã]o[ \t]+(?:j[aá][ \t]+)?(?:paguei|quitei|depositei|passei|fiz|efetuei|realizei|mandei|enviei|transferi|foi|foram|est[aá]|est[aã]o|t[aá]|t[aã]o|consegui)\b/i.test(
      t
    ) ||
    /\b(?:paguei|quitei|depositei|passei|fiz|efetuei|realizei|mandei|enviei|transferi|pag[oa]s?)[ \t]+n[aã]o(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    )
  ) {
    return false;
  }

  const cmdNorm = normalizeCommandText(t);
  if (cmdNorm === 'pago' || cmdNorm === 'paga' || cmdNorm === 'pagos') {
    return true;
  }

  const isQuestion = t.endsWith('?');
  const hasConditionalOfferPrefix =
    /\b(?:eu|se|caso)[ \t]+/i.test(t) || /\bpor[ \t]+(?:r\$[ \t]*)?\d/i.test(t);

  if (
    !isQuestion &&
    !hasConditionalOfferPrefix &&
    (/^[ \t]*pag[oa]s?(?:[ \t]+(?:o|a|os|as|meu|minha)[ \t]+(?:pix|pagamento|cobran[cç]a|valor)\b|[!,.:;-]+[ \t]*(?:o[ \t]+|meu[ \t]+|pix\b|pagamento\b|r\$\s*\d|\d))/i.test(
      t
    ) ||
      /^[ \t]*(?:feit[oa]s?|realizad[oa]s?|efetuad[oa]s?|enviad[oa]s?|transferid[oa]s?|depositad[oa]s?|quitad[oa]s?|conclu[ií]d[oa]s?)(?:[!,.:;-]+[ \t]*|[ \t]+)(?:(?:o|a|os|as|meu|minha)[ \t]+)?(?:pix|pagamento|cobran[cç]a|valor|r\$[ \t]*\d|\d)/i.test(
        t
      ) ||
      /(?:(?<!\w)r\$[ \t]*\d[\d.,]*|(?<![-\w.,])\d[\d.,]*)[ \t]*(?:reais[ \t]+)?(?:j[aá][ \t]+)?(?:(?:foi|foram|est[aá]|est[aã]o|t[aá]|t[aã]o)[ \t]+)?(?:pago(?![ \t]+(?:agora|hoje|amanh[aã](?![A-Za-zÀ-ÿ0-9])|depois|se\b))|paga|pagos|pagas|enviad[oa]s?|transferid[oa]s?|feit[oa]s?|realizad[oa]s?|efetuad[oa]s?|depositad[oa]s?|quitad[oa]s?|conclu[ií]d[oa]s?)\b/i.test(
        t
      ))
  ) {
    return true;
  }

  return (
    /\b(?:paguei|quitei|depositei|passei)\b/i.test(t) ||
    /\bcomprovante\b/i.test(t) ||
    /\bsegue(?:[ \t]+(?:a[ií]|aqui|anexo|abaixo))?[ \t]+(?:(?:o|a|os|meu|minha)[ \t]+)?(?:pix|pagamento|comprovante|recibo|transfer[eê]ncia|dep[oó]sito)\b/i.test(
      t
    ) ||
    /\b(?:t[aá]|est[aá]|foi|foram|est[aã]o|t[aã]o)[ \t]+(?:pag[oa]s?|enviad[oa]s?|transferid[oa]s?|feit[oa]s?|realizad[oa]s?|efetuad[oa]s?|depositad[oa]s?|quitad[oa]s?|conclu[ií]d[oa]s?)\b/i.test(
      t
    ) ||
    /\b(?:pix|pagamento|cobran[cç]a|transfer[eê]ncia|transa[cç][aã]o|dep[oó]sito|valor)(?:[ \t]+pix)?(?:[ \t]+d[eo][ \t]+(?:r\$[ \t]*)?[\d.,]+(?:[ \t]+reais)?)?[ \t]+(?:j[aá][ \t]+)?(?:(?:foi|foram|est[aá]|est[aã]o|t[aá]|t[aã]o)[ \t]+)?(?:pag[oa]s?|enviad[oa]s?|feit[oa]s?|realizad[oa]s?|efetuad[oa]s?|conclu[ií]d[oa]s?|transferid[oa]s?|depositad[oa]s?|quitad[oa]s?)\b/i.test(
      t
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:j[aá][ \t]+)?(?:fiz|efetuei|realizei|mandei|enviei|transferi)(?:[ \t]+(?!n[aã]o(?![A-Za-zÀ-ÿ0-9])|nem\b|nunca\b|errad[oa]\b|outr[oa]\b)[A-Za-zÀ-ÿ]+){0,6}[ \t]+(?:pix|pagamento|dep[oó]sito|transfer[eê]ncia|cobran[cç]a|valor|comprovante|r\$[ \t]*\d|\d)/i.test(
      t
    ) ||
    /\bacabei[ \t]+de[ \t]+(?:pagar|fazer|enviar|mandar|transferir|depositar|passar)\b/i.test(t)
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
