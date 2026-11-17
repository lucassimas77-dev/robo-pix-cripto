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
const NUM_RIGHT =
  '(?![.,]\\d|\\d|[-\\wÀ-ÿºª°\\uFE0F\\u20E3]|[ \\t]*%|\\.[a-zA-Z]|\\/[A-Za-zÀ-ÿ0-9])';

const DECORATIVE_EMOJI_RE =
  /(?:\p{Extended_Pictographic}|\p{Emoji_Presentation}|[\u2139\u2611\u2705\u2714\u274C\u274E]|\u200D|[\u{1F3FB}-\u{1F3FF}]|\uFE0F(?!\u20E3))+/gu;

function normalizeHorizontalSpaces(input: string): string {
  return input
    .normalize('NFC')
    .replace(/[\u00AD\u034F\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, '')
    .replace(/[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/g, ' ');
}

function stripDecorativeEmojis(input: string): string {
  return input.replace(DECORATIVE_EMOJI_RE, ' ');
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
  'pila',
  'pilas',
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
  'minutinho',
  'minutinhos',
  'seg',
  'segundo',
  'segundos',
  'segundinho',
  'segundinhos',
  'instante',
  'instantes',
  'instantinho',
  'instantinhos',
  'hora',
  'horas',
  'horinha',
  'horinhas',
  'dia',
  'dias',
  'semana',
  'semanas',
  'mes',
  'mês',
  'meses',
  'ano',
  'anos',
  'kg',
  'quilo',
  'quilos',
  'g',
  'grama',
  'gramas',
  'mg',
  'l',
  'litro',
  'litros',
  'ml',
  'm',
  'metro',
  'metros',
  'cm',
  'mm',
  'km',
  'quilometro',
  'quilômetro',
  'quilometros',
  'quilômetros',
  'm2',
  'm²',
  'm3',
  'm³',
  'cm2',
  'cm²',
  'ton',
  'tonelada',
  'toneladas',
  'ha',
  'hectare',
  'hectares',
  'arroba',
  'arrobas',
  'alqueire',
  'alqueires',
  'polegada',
  'polegadas',
  'gb',
  'giga',
  'gigas',
  'gigabyte',
  'gigabytes',
  'mb',
  'mega',
  'megas',
  'megabyte',
  'megabytes',
  'tb',
  'terabyte',
  'terabytes',
  'kb',
  'mbps',
  'gbps',
  'w',
  'watt',
  'watts',
  'kw',
  'kwh',
  'kva',
  'v',
  'volt',
  'volts',
  'kv',
  'mah',
  'ampere',
  'amperes',
  'hz',
  'khz',
  'mhz',
  'ghz',
  'btu',
  'btus',
  'cv',
  'cilindrada',
  'cilindradas',
  'kcal',
  'caloria',
  'calorias',
  'grau',
  'graus',
  'camisa',
  'camisas',
  'camiseta',
  'camisetas',
  'calca',
  'calça',
  'calcas',
  'calças',
  'bermuda',
  'bermudas',
  'vestido',
  'vestidos',
  'blusa',
  'blusas',
  'jaqueta',
  'jaquetas',
  'par',
  'pares',
  'sapato',
  'sapatos',
  'tenis',
  'tênis',
  'chinelo',
  'chinelos',
  'pneu',
  'pneus',
  'roda',
  'rodas',
  'garrafa',
  'garrafas',
  'lata',
  'latas',
  'saco',
  'sacos',
  'sacola',
  'sacolas',
  'fardo',
  'fardos',
  'pote',
  'potes',
  'frasco',
  'frascos',
  'cartela',
  'cartelas',
  'comprimido',
  'comprimidos',
  'capsula',
  'cápsula',
  'capsulas',
  'cápsulas',
  'dose',
  'doses',
  'passagem',
  'passagens',
  'diaria',
  'diária',
  'diarias',
  'diárias',
  'noite',
  'noites',
  'mensalidade',
  'mensalidades',
  'fatura',
  'faturas',
  'boleto',
  'boletos',
  'conta',
  'contas',
  'nota',
  'notas',
  'duplicata',
  'duplicatas',
  'carnê',
  'carnês',
  'duvida',
  'dúvida',
  'duvidas',
  'dúvidas',
  'pergunta',
  'perguntas',
  'tentativa',
  'tentativas',
  'erro',
  'erros',
  'foto',
  'fotos',
  'imagem',
  'imagens',
  'print',
  'prints',
  'arquivo',
  'arquivos',
  'video',
  'vídeo',
  'videos',
  'vídeos',
  'pagina',
  'página',
  'paginas',
  'páginas',
  'folha',
  'folhas',
  'ponto',
  'pontos',
  'estrela',
  'estrelas',
  'cliente',
  'clientes',
  'usuario',
  'usuário',
  'usuarios',
  'usuários',
  'mesa',
  'mesas',
  'cadeira',
  'cadeiras',
  'quarto',
  'quartos',
  'sala',
  'salas',
  'lote',
  'lotes',
  'pessoa',
  'pessoas',
  'lugar',
  'lugares',
  'centimetro',
  'centímetro',
  'centimetros',
  'centímetros',
  'milimetro',
  'milímetro',
  'milimetros',
  'milímetros',
  'decimetro',
  'decímetro',
  'decimetros',
  'decímetros',
  'miligrama',
  'miligramas',
  'micrograma',
  'microgramas',
  'mcg',
  'mililitro',
  'mililitros',
  'quilometro',
  'quilômetro',
  'quilometros',
  'quilômetros',
  'polegada',
  'polegadas',
  'milha',
  'milhas',
  'grau',
  'graus',
  'celsius',
  'fahrenheit',
  'megapixel',
  'megapixels',
]);

const PLURAL_DETERMINER_WORDS = new Set([
  'os',
  'as',
  'uns',
  'umas',
  'esses',
  'essas',
  'estes',
  'estas',
  'aqueles',
  'aquelas',
  'meus',
  'minhas',
  'seus',
  'suas',
  'nossos',
  'nossas',
  'pelos',
  'pelas',
  'nos',
  'nas',
  'dos',
  'das',
  'aos',
  'às',
]);

const ENUMERATION_PREV_WORDS = new Set([
  ...PLURAL_DETERMINER_WORDS,
  'entre',
  'dia',
  'dias',
  'item',
  'itens',
  'kit',
  'kits',
  'mesa',
  'mesas',
  'parcela',
  'parcelas',
  'opcao',
  'opção',
  'opcoes',
  'opções',
  'quarto',
  'quartos',
  'sala',
  'salas',
  'lote',
  'lotes',
  'tamanho',
  'tamanhos',
  'tam',
  'caixa',
  'caixas',
  'pacote',
  'pacotes',
  'unidade',
  'unidades',
  'peca',
  'peça',
  'pecas',
  'peças',
  'produto',
  'produtos',
  'numero',
  'número',
  'numeros',
  'números',
  'codigo',
  'código',
  'codigos',
  'códigos',
  'pedido',
  'pedidos',
  'ingresso',
  'ingressos',
  'cota',
  'cotas',
  'bloco',
  'blocos',
  'quadra',
  'quadras',
  'casa',
  'casas',
  'loja',
  'lojas',
  'andar',
  'andares',
  'piso',
  'pisos',
  'pessoa',
  'pessoas',
  'lugar',
  'lugares',
  'camisa',
  'camisas',
  'camiseta',
  'camisetas',
  'calca',
  'calça',
  'calcas',
  'calças',
  'sapato',
  'sapatos',
  'tenis',
  'tênis',
  'aro',
  'aros',
  'hora',
  'horas',
  'minuto',
  'minutos',
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
        const isPrecededByMil =
          idx >= 2 &&
          /(?:^|[^A-Za-zÀ-ÿ0-9])mil(?:[ \t]+e|[ \t]*,)?[ \t]+$/i.test(
            tokens.slice(Math.max(0, idx - 4), idx).join('')
          );
        const isSubFollowedByCentavos =
          sub.endIdx + 2 < tokens.length &&
          /^[ \t]+$/.test(tokens[sub.endIdx + 1]) &&
          /^centavos?$/i.test(tokens[sub.endIdx + 2]);
        if (!(isPrecededByMil && isSubFollowedByCentavos)) {
          return { value: base + sub.value, endIdx: sub.endIdx, singleUm: false };
        }
      }
    }
    return { value: base, endIdx: idx, singleUm: false };
  }
  return readSubHundredTokens(tokens, idx);
}

function isGluedLeftIdentifierBoundary(tokens: string[], wordStartIdx: number): boolean {
  if (wordStartIdx <= 0) return false;
  const prevSep = tokens[wordStartIdx - 1];
  // Bloqueia apenas tokens colados sem espaço a identificadores/rotas/handles ("auto-dois", "/dois", "@dois", "foo.dois")
  if (/[-/@]$/.test(prevSep)) return true;
  if (prevSep === '.' && wordStartIdx >= 2 && /^[A-Za-zÀ-ÿ\d]/.test(tokens[wordStartIdx - 2])) {
    return true;
  }
  return false;
}

function isGluedRightIdentifierBoundary(tokens: string[], wordEndIdx: number): boolean {
  if (wordEndIdx + 1 >= tokens.length) return false;
  const nextSep = tokens[wordEndIdx + 1];
  const hasAdjacentTokenAfter =
    wordEndIdx + 2 < tokens.length && /^[A-Za-zÀ-ÿ\d]/.test(tokens[wordEndIdx + 2]);
  // Ponto final (".", "...", ". Obrigado!") e travessão espaçado (" - ") NUNCA bloqueiam numerais por extenso!
  if (/^[@/]/.test(nextSep)) return true;
  if ((nextSep === '-' || nextSep === '.') && hasAdjacentTokenAfter) return true;
  return false;
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
    if (isGluedLeftIdentifierBoundary(tokens, i) || isGluedRightIdentifierBoundary(tokens, endIdx)) {
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
    const nextNextWordIdx =
      endWordPos >= 0 &&
      endWordPos + 2 < wordIndices.length &&
      wordIndices[endWordPos + 2] - wordIndices[endWordPos + 1] <= 2
        ? wordIndices[endWordPos + 2]
        : -1;
    const nextNextWord = nextNextWordIdx >= 0 ? tokens[nextNextWordIdx].toLowerCase() : '';

    // Pronomes plurais ("nós dois", "os dois") e artigo feminino plural antes de substantivo comum ("as dez fotos")
    // permanecem bloqueados; já preposições de hora ("às", "das", "pelas", "as 10", "as duas e trinta") convertem para dígitos
    // para que o limpador completo de horários remova a expressão inteira sem deixar os minutos soltos!
    const isMinutesToHourPreposition =
      prevWord === 'as' && ['para', 'pra'].includes(prevPrevWord);
    const isPluralArticleBeforeNoun =
      prevWord === 'as' &&
      !isMinutesToHourPreposition &&
      nextWord.length > 0 &&
      nextWord !== 'e' &&
      nextWord !== 'da' &&
      !CURRENCY_OR_SCALE_WORDS.has(nextWord) &&
      !QTY_OR_UNIT_WORDS.has(nextWord);

    const blockedPronoun =
      !CURRENCY_OR_SCALE_WORDS.has(nextWord) &&
      !QTY_OR_UNIT_WORDS.has(nextWord) &&
      (isPluralArticleBeforeNoun ||
        ['nos', 'nós', 'voces', 'vocês', 'eles', 'elas', 'ambos', 'ambas', 'uns'].includes(
          prevWord
        ) ||
        (prevWord === 'os' && value === 2));

    const isHourPreposition =
      ['às', 'à', 'pelas', 'das', 'pras', 'umas'].includes(prevWord) ||
      (prevWord === 'as' && !isMinutesToHourPreposition);

    // Centavos coloquiais por extenso: "dez e cinquenta" -> "10,50", "vinte e cinco e cinquenta" -> "25,50"
    // Nunca combina como centavos quando for horário ("às duas e trinta", "três e vinte faço o pix"), após "mil", intervalo ou enumeração!
    const isAfterThousandScale =
      prevWord === 'mil' || (prevWord === 'e' && prevPrevWord === 'mil');
    const isPrecededByEnumerationContext =
      ENUMERATION_PREV_WORDS.has(prevWord) ||
      (prevWord === 'de' && PLURAL_DETERMINER_WORDS.has(prevPrevWord));

    if (
      !blockedPronoun &&
      !isHourPreposition &&
      !isAfterThousandScale &&
      !isPrecededByEnumerationContext &&
      endIdx + 4 < tokens.length &&
      /^[ \t]+$/.test(tokens[endIdx + 1]) &&
      tokens[endIdx + 2].toLowerCase() === 'e' &&
      /^[ \t]+$/.test(tokens[endIdx + 3]) &&
      /^[A-Za-zÀ-ÿ]+$/.test(tokens[endIdx + 4])
    ) {
      const centsSub = readSubHundredTokens(tokens, endIdx + 4);
      if (centsSub) {
        const centsEndWordPos = wordPosMap.get(centsSub.endIdx) ?? -1;
        const wordAfterCents =
          centsEndWordPos >= 0 &&
          centsEndWordPos + 1 < wordIndices.length &&
          wordIndices[centsEndWordPos + 1] - centsSub.endIdx <= 2
            ? tokens[wordIndices[centsEndWordPos + 1]].toLowerCase()
            : '';
        const word2AfterCents =
          centsEndWordPos >= 0 &&
          centsEndWordPos + 2 < wordIndices.length &&
          wordIndices[centsEndWordPos + 2] - wordIndices[centsEndWordPos + 1] <= 2
            ? tokens[wordIndices[centsEndWordPos + 2]].toLowerCase()
            : '';
        const hasExplicitCentavos = wordAfterCents === 'centavo' || wordAfterCents === 'centavos';
        const isDayPeriodAfter =
          wordAfterCents === 'da' &&
          ['manha', 'manhã', 'tarde', 'noite', 'madrugada'].includes(word2AfterCents);
        const isClockHourBeforeAction =
          !hasExplicitCentavos &&
          value >= 1 &&
          value <= 23 &&
          centsSub.value <= 59 &&
          !['de', 'por', 'valor', 'total', 'sao', 'são', 'fica', 'ficou', 'custa'].includes(
            prevWord
          ) &&
          [
            'faco',
            'faço',
            'mando',
            'envio',
            'pago',
            'passo',
            'transfiro',
            'deposito',
            'vou',
            'eu',
          ].includes(wordAfterCents);
        const blockedCentsNext =
          isDayPeriodAfter ||
          isClockHourBeforeAction ||
          [
            'mil',
            'milhao',
            'milhão',
            'milhoes',
            'milhões',
            'hora',
            'horas',
            'horinha',
            'horinhas',
            'min',
            'mins',
            'minuto',
            'minutos',
            'minutinho',
            'minutinhos',
          ].includes(wordAfterCents);
        if (
          !blockedCentsNext &&
          !isGluedRightIdentifierBoundary(tokens, centsSub.endIdx) &&
          (hasExplicitCentavos || centsSub.value >= 20)
        ) {
          const formattedDec = `${value},${String(centsSub.value).padStart(2, '0')}`;
          if (hasExplicitCentavos) {
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
      const recentOutTail = out.slice(-8).join('');
      const isMinutesBeforeOne =
        (prevWord === 'pra' ||
          prevWord === 'para' ||
          (prevWord === 'a' && ['para', 'pra'].includes(prevPrevWord))) &&
        !/(?:de|por|valor|r\$)[ \t]*\d+[ \t]+(?:para(?:[ \t]+a)?|pra(?:[ \t]+a)?)[ \t]*$/i.test(
          recentOutTail
        ) &&
        /(?:^|[^\d.,])(?:[0-5]?\d)(?:[ \t]*min(?:utos?)?)?[ \t]+(?:para(?:[ \t]+a)?|pra(?:[ \t]+a)?)[ \t]*$/i.test(
          recentOutTail
        ) &&
        [
          '',
          'e',
          'da',
          'mando',
          'faço',
          'faco',
          'pago',
          'envio',
          'passo',
          'transfiro',
          'deposito',
          'vou',
          'eu',
          'ja',
          'já',
          'ai',
          'aí',
        ].includes(nextWord);
      const isSingularOneHour =
        tokens[i].toLowerCase() === 'uma' &&
        (prevWord === 'à' ||
          prevWord === 'umas' ||
          isMinutesBeforeOne ||
          (prevWord === 'a' && ['e', 'da', 'mando', 'faço', 'faco', 'pago', 'envio'].includes(nextWord)));
      const isRangeOrChoiceConnector =
        (tokens[i].toLowerCase() === 'um' && nextWord === 'e' && nextNextWord === 'meio') ||
        (['e', 'a', 'à', 'ate', 'até', 'ou', 'mais', 'menos'].includes(nextWord) &&
          ((nextNextWordIdx >= 0 &&
            (readSubThousandTokens(tokens, nextNextWordIdx) !== null ||
              CURRENCY_OR_SCALE_WORDS.has(nextNextWord))) ||
            (endWordPos >= 0 &&
              endWordPos + 1 < wordIndices.length &&
              wordIndices[endWordPos + 1] + 2 < tokens.length &&
              /^\d/.test(tokens[wordIndices[endWordPos + 1] + 2]))));

      const isTimeScaleWord = [
        'minuto',
        'minutos',
        'minutinho',
        'minutinhos',
        'hora',
        'horas',
        'horinha',
        'horinhas',
        'segundo',
        'segundos',
        'segundinho',
        'segundinhos',
        'instante',
        'instantes',
        'instantinho',
        'instantinhos',
        'dia',
        'dias',
        'semana',
        'semanas',
        'mes',
        'mês',
        'meses',
        'ano',
        'anos',
      ].includes(nextWord);

      shouldConvert =
        CURRENCY_OR_SCALE_WORDS.has(nextWord) ||
        isTimeScaleWord ||
        isSingularOneHour ||
        (prevWord === 'e' && prevPrevWord === 'mil') ||
        isRangeOrChoiceConnector;
    } else {
      shouldConvert = !blockedPronoun;
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

const FOREIGN_OR_CRYPTO_NO_DEPIX =
  '(?:us\\$|u\\$|usd|eur|gbp|ars|cad|aud|chf|jpy|cny|pyg|usdt|tether|usdc|dai|busd|rlusd|btc|l-?btc|bitcoins?|sats?|satoshis?|eth|ether|ethereum|sol|solana|bnb|xrp|trx|tron|ltc|doge|ada|cardano|avax|shib|toncoin|xmr|monero|matic|pol|d[oó]lar(?:es)?|euros?|libras?|pesos?|ienes?)';

const FOREIGN_OR_CRYPTO_UNAMBIGUOUS_NO_DEPIX =
  '(?:us\\$|u\\$|usd|eur|gbp|jpy|cny|pyg|usdt|tether|usdc|busd|rlusd|btc|l-?btc|bitcoins?|satoshis?|ethereum|solana|monero|cardano|doge|d[oó]lar(?:es)?|euros?|ienes?)';

const FOREIGN_OR_CRYPTO_TOKEN = `(?:${FOREIGN_OR_CRYPTO_NO_DEPIX}|depix)`;

const FOREIGN_CURRENCY_PREFIX_RE = new RegExp(
  `(?:(?<![A-Za-zÀ-ÿ])${FOREIGN_OR_CRYPTO_TOKEN}(?![A-Za-zÀ-ÿ])(?:[ \\t]+de)?|[€£¥]|(?<!(?<![A-Za-zÀ-ÿ])[rR])\\$)[ \\t]*\\d`,
  'i'
);

const FOREIGN_CURRENCY_SUFFIX_RE = new RegExp(
  `(?<![\\d.,])\\d+(?:[.,]\\d+)*(?:[ \\t]*(?:mil|milh(?:[aã]o|[oõ]es)))?(?:[ \\t]+de)?[ \\t]*(?:${FOREIGN_OR_CRYPTO_TOKEN}(?![A-Za-zÀ-ÿ0-9])|[€£¥]|(?<!(?<![A-Za-zÀ-ÿ])[rR])\\$)`,
  'i'
);

const FOREIGN_CONVERSION_TARGET_RE = new RegExp(
  `(?:(?:r\\$[ \\t]*\\d[\\d.,]*(?![\\d.,])|(?<![\\d.,])\\d[\\d.,]*(?![\\d.,])(?:[ \\t]*(?:mil|milh(?:[aã]o|[oõ]es)))?[ \\t]*(?:reais|real|brl|contos?|pilas?))[ \\t]+(?:(?:em|para|pra|por)[ \\t]+${FOREIGN_OR_CRYPTO_TOKEN}|de[ \\t]+${FOREIGN_OR_CRYPTO_NO_DEPIX}|(?:d[aá]|d[aã]o|rende|vira|compra|vale|equivalem?[ \\t]+a)(?:[ \\t]+(?:quantos?|quantas?|quanto[ \\t]+de))?[ \\t]+${FOREIGN_OR_CRYPTO_TOKEN})(?![A-Za-zÀ-ÿ0-9])|(?<![A-Za-zÀ-ÿ0-9])${FOREIGN_OR_CRYPTO_NO_DEPIX}(?![A-Za-zÀ-ÿ0-9])(?:[ \\t]+(?:no[ \\t]+pix|agora|hoje)){0,2}[ \\t]+(?:com|por|em|de|pelo[ \\t]+valor[ \\t]+de)[ \\t]+(?:r\\$[ \\t]*\\d[\\d.,]*(?![\\d.,])|\\d[\\d.,]*(?![\\d.,])[ \\t]*(?:mil|milh(?:[aã]o|[oõ]es)|reais|real|brl|contos?|pilas?)(?![A-Za-zÀ-ÿ0-9])))`,
  'i'
);

const FOREIGN_EXCHANGE_QUOTE_RE = new RegExp(
  `(?<![A-Za-zÀ-ÿ0-9])${FOREIGN_OR_CRYPTO_NO_DEPIX}(?![A-Za-zÀ-ÿ0-9])(?:[ \\t]+(?:hoje|agora|comercial|turismo|paralelo|oficial|ptax|spot|no[ \\t]+pix|em[ \\t]+reais|est[aá]|t[aá]|ta|[eé]|custa|sai|fica|bateu|fechou|abriu|vale|cotad[oa]|a|por|em)(?![A-Za-zÀ-ÿ0-9])|[ \\t]*[:=-]){1,4}[ \\t]*(?:r\\$[ \\t]*)?\\d|(?<![A-Za-zÀ-ÿ0-9])cota[cç][aã]o(?![A-Za-zÀ-ÿ0-9])`,
  'i'
);

const FOREIGN_TRADE_CLAUSE_RE = new RegExp(
  `(?<![A-Za-zÀ-ÿ0-9])(?:(?:comprar|compra|compro|vender|venda|vendo|converter|converto|convers[aã]o|trocar|troco|c[aâ]mbio|cotar|adquirir)(?:[ \\t]+(?:um[ \\t]+pouco[ \\t]+de|uns|umas|alguns|algumas|os?|as?|meus?|minhas?|em|de|por|para|pra))?[ \\t]+(?!(?<=de[ \\t])sol(?![A-Za-zÀ-ÿ0-9]))${FOREIGN_OR_CRYPTO_NO_DEPIX}|${FOREIGN_OR_CRYPTO_UNAMBIGUOUS_NO_DEPIX})(?![A-Za-zÀ-ÿ0-9])`,
  'i'
);

function hasForeignCurrencyOrCrypto(input: string): boolean {
  return (
    FOREIGN_CURRENCY_PREFIX_RE.test(input) ||
    FOREIGN_CURRENCY_SUFFIX_RE.test(input) ||
    FOREIGN_CONVERSION_TARGET_RE.test(input) ||
    FOREIGN_EXCHANGE_QUOTE_RE.test(input) ||
    FOREIGN_TRADE_CLAUSE_RE.test(input)
  );
}

const PHYSICAL_OR_SPEC_SUFFIX_UNIT_PATTERN =
  '(?:x|vezes|parcelas?|itens?|unidades?|pe[cç]as?|produtos?|pacotes?|caixas?|kits?|ingressos?|cotas?|kg|quilos?|g|gramas?|mg|miligramas?|mcg|microgramas?|ton|toneladas?|ha|hectares?|arrobas?|alqueires?|l|litros?|ml|mililitros?|decilitros?|m|metros?(?:[ \\t]+(?:quadrados?|c[uú]bicos?))?|m2|m²|m3|m³|cm|cent[ií]metros?|cm2|cm²|mm|mil[ií]metros?|dec[ií]metros?|micr[oô]metros?|km|quil[oô]metros?|milhas?|polegadas?|jardas?|on[cç]as?|oz|lbs?|quilates?|gb|gigas?|gigabytes?|mb|megas?|megabytes?|tb|terabytes?|kb|mbps|gbps|w|watts?|kw|quilowatts?|kwh|kva|mw|megawatts?|v|volts?|kv|mah|amperes?|ohms?|hz|khz|mhz|ghz|btu|btus|cv|hps?|cilindradas?|psi|rpm|fps|dpi|mp|megapixels?|pixels?|px|kcal|calorias?|graus?(?:[ \\t]*(?:celsius|cent[ií]grados?|fahrenheit))?|[º°][ \\t]*[cfk]|celsius|fahrenheit|camisas?|camisetas?|cal[cç]as?|bermudas?|vestidos?|blusas?|jaquetas?|pares?|sapatos?|t[eê]nis|chinelos?|pneus?|rodas?|garrafas?|latas?|sacos?|sacolas?|fardos?|potes?|frascos?|cartelas?|comprimidos?|c[aá]psulas?|doses?|passagens?|di[aá]rias?|noites?|mensalidades?|faturas?|boletos?|contas?|notas?|duplicatas?|carn[ê]s?|d[uú]vidas?|perguntas?|tentativas?|erros?|fotos?|imagens?|prints?|arquivos?|v[ií]deos?|p[aá]ginas?|folhas?|pontos?|estrelas?|clientes?|usu[aá]rios?|mesas?|cadeiras?|quartos?|salas?|lotes?|pessoas?|lugares?)';

const PCT_REGEX = new RegExp(
  `${NUM_LEFT}(?:${NUM_CORE})[ \\t]*(?:%|por[ \\t]*cento(?![A-Za-zÀ-ÿ0-9])|porcento(?![A-Za-zÀ-ÿ0-9]))`,
  'i'
);

const QTY_WITH_UNIT_PRICE_RE = new RegExp(
  `(?<![\\d.,])\\d+(?:[.,]\\d+)?(?![.,]\\d|\\d)[ \\t]*${PHYSICAL_OR_SPEC_SUFFIX_UNIT_PATTERN}(?:[ \\t]+e[ \\t]+mei[oa])?[ \\t]+(?:(?:de|por|a|cada)[ \\t]+(?:r\\$[ \\t]*)?|r\\$[ \\t]*)\\d`,
  'i'
);

const SUFFIX_UNIT_STRIP_RE = new RegExp(
  `(?<![\\d.,])\\d+(?:[.,]\\d+)*(?![.,]\\d|\\d)[ \\t]*${PHYSICAL_OR_SPEC_SUFFIX_UNIT_PATTERN}(?![A-Za-zÀ-ÿ0-9])`,
  'gi'
);

const ALL_TOKENS_REGEX = new RegExp(`${NUM_LEFT}(${NUM_CORE})${NUM_RIGHT}`, 'g');

const ACCOUNT_DEBITED_REPORT_RE =
  /(?<![A-Za-zÀ-ÿ0-9])(?:descontou|descontaram|debitou|debitaram|(?:foi|foram)[ \t]+(?:descontad[oa]s?|debitad[oa]s?)|(?:saiu|sa[ií]ram)(?:[ \t]+(?:os?|as?|r\$|\d[\d.,]*|vezes|x|em|duplicidade|reais|real|valor|dinheiro|pagamento|pix)){0,8}[ \t]+(?:da[ \t]+(?:minha[ \t]+)?conta|do[ \t]+(?:meu[ \t]+)?(?:banco|saldo)))(?![A-Za-zÀ-ÿ0-9])/i;

const OPT_CLITIC_PRONOUN = '(?:(?:te|lhe|lhes)[ \\t]+)?';

const NEGATED_SETTLEMENT_STATUS_CORE =
  'n[aã]o[ \\t]+(?:j[aá][ \\t]+)?(?:(?:te|lhe|lhes|me|nos)[ \\t]+)?(?:passou|passaram|concluiu|conclu[ií]ram|completou|completaram|finalizou|finalizaram|processou|processaram|confirmou|confirmaram|aprovou|aprovaram|autorizou|autorizaram|liberou|liberaram|deixou|deixaram|permitiu|permitiram|aceitou|aceitaram|compensou|compensaram|creditou|creditaram|caiu|ca[ií]ram|cairam|entrou|entraram|bateu|bateram|chegou|chegaram|recebeu|receberam|efetivou|liquidou|vai|foi(?![ \\t]+(?:eu|ele|ela|ontem|hoje)(?![A-Za-zÀ-ÿ0-9]))|foi[ \\t]+poss[ií]vel|(?:est[aá]|est[aã]o|t[aá]|t[aã]o)[ \\t]+(?:aprovando|autorizando|passando|completando|concluindo|finalizando|liberando|aceitando|processando|confirmando|compensando|indo|entrando|caindo)|deu[ \\t]+certo|(?:(?:foi|foram|est[aá]|est[aã]o|t[aá]|t[aã]o)[ \\t]+)?(?:aprovad[oa]s?|autorizad[oa]s?|liberad[oa]s?|aceit[oa]s?|permitid[oa]s?|confirmad[oa]s?|compensad[oa]s?|processad[oa]s?|creditad[oa]s?|recebid[oa]s?|conclu[ií]d[oa]s?|efetuad[oa]s?|realizad[oa]s?|enviad[oa]s?|transferid[oa]s?|depositad[oa]s?|quitad[oa]s?|identificad[oa]s?))';

const EXPIRED_CHARGE_REPORT_CLAUSE =
  '(?:expirou|expiraram|expirad[oa]s?|(?:venceu|venceram)[ \\t]+(?:o[ \\t]+|a[ \\t]+|meu[ \\t]+|minha[ \\t]+|esse[ \\t]+|essa[ \\t]+)?(?:pix|pagamento|cobran[cç]a|link|qr(?:[ \\t]*code)?|c[oó]digo|chave)|(?:pix|pagamento|cobran[cç]a|link|qr(?:[ \\t]*code)?|c[oó]digo|chave)(?:[ \\t]+(?:d[eo]s?|da|no|na|r\\$|\\d[\\d.,]*|reais|real|contos?|pilas?)){0,4}[ \\t]+(?:(?:(?:est[aá]|t[aá]|fica|ficou|continua)[ \\t]+)?(?:dando|aparecendo|acusando)[ \\t]+(?:como[ \\t]+)?|(?:deu|est[aá]|t[aá]|fica|ficou|foi|aparece|apareceu|consta|diz)[ \\t]+(?:como[ \\t]+)?)?(?:venceu|venceram|vencid[oa]s?|inv[aá]lid[oa]s?|quebrad[oa]s?|indispon[ií]vel|inexistente))';

const FINANCIAL_RETURNED_REPORT_CLAUSE =
  '(?:(?:voltou|voltaram|retornou|retornaram)(?:[ \\t]+(?:os?|as?|r\\$|\\d[\\d.,]*|reais|real|contos?|pilas?|valor|dinheiro|pagamento|pix)){0,6}[ \\t]+(?:pra|para|na|[aà])[ \\t]+(?:minha[ \\t]+)?(?:conta|banco|saldo)|(?:pix|pagamento|transfer[eê]ncia|dep[oó]sito|transa[cç][aã]o|valor|dinheiro)(?:[ \\t]+(?:d[eo]s?|da|no|na|que[ \\t]+(?:eu[ \\t]+)?(?:fiz|mandei|enviei|paguei|passei|transferi)|r\\$|\\d[\\d.,]*|reais|real|contos?|pilas?)){0,6}[ \\t]+(?:acabou[ \\t]+de[ \\t]+)?(?:voltar|voltou|voltaram|retornar|retornou|retornaram)|(?:(?:os?|meus?)[ \\t]+)?(?:r\\$[ \\t]*\\d[\\d.,]*|\\d[\\d.,]*[ \\t]+(?:reais|real|contos?|pilas?))[ \\t]+(?:acabou[ \\t]+de[ \\t]+|acabaram[ \\t]+de[ \\t]+)?(?:voltar|voltou|voltaram|retornar|retornou|retornaram)|(?:voltou|voltaram|retornou|retornaram)[ \\t]+(?:(?:o|os|meu|meus|esse|esses)[ \\t]+)?(?:(?:pix|pagamento|valor|dinheiro)(?:[ \\t]+d[eo][ \\t]+(?:r\\$[ \\t]*)?\\d[\\d.,]*)?|r\\$[ \\t]*\\d[\\d.,]*|\\d[\\d.,]*[ \\t]+(?:reais|real|contos?|pilas?)))';

const OUTGOING_PAYOUT_OR_DEBT_RE =
  /(?<![A-Za-zÀ-ÿ0-9])(?:(?:para|pra|pro)[ \t]+(?:a[ \t]+|o[ \t]+)?(?:minha[ \t]+(?:conta|chave|carteira)|meu[ \t]+pix)|(?:na|no)[ \t]+(?:a[ \t]+|o[ \t]+)?minha[ \t]+chave|(?:minha[ \t]+chave(?:[ \t]+(?:de[ \t]+)?pix)?|meu[ \t]+pix)[ \t]*(?:[eé](?![A-Za-zÀ-ÿ0-9])|[:=-])|(?:segue|essa[ \t]+[eé]|aqui[ \t]+est[aá])[ \t]+(?:a[ \t]+)?minha[ \t]+chave|(?:mand[ae]|mandar|envi[ae]|enviar|faz|fa[cç]a|fazer|transfere|transferir|deposita|depositar|paga|pague|pagar|cai|cair)(?:[ \t]+(?:os?|as?|um|uma|r\$|\d[\d.,]*|reais|real|contos?|pilas?|pix|valor|dinheiro)){0,5}[ \t]+(?:na|no)[ \t]+(?:a[ \t]+|o[ \t]+)?(?:minha[ \t]+conta|meu[ \t]+pix)|(?:voc[eê][ \t]+|vc[ \t]+|tu[ \t]+)?me[ \t]+(?:deve|devendo|paga|pague|transfere|transferir|deposita|depositar|ressarce|ressarcir|devolve|devolver|reembolsa|reembolsar|estorna|estornar)|(?:me[ \t]+)?emprest(?:ar|a|e|ou))(?![A-Za-zÀ-ÿ0-9])/i;

const PAYMENT_FAILURE_OR_REFUND_RE = new RegExp(
  `(?<![A-Za-zÀ-ÿ0-9])(?:deu[ \\t]+(?:erro|errad[oa]|falha|problema|ruim)|(?:tive|teve|tivemos|ocorreu|apresentou|apareceu|dando|est[aá][ \\t]+com|t[aá][ \\t]+com)[ \\t]+(?:um[ \\t]+|algum[ \\t]+)?(?:erro|falha|problemas?)|(?<!(?<![A-Za-zÀ-ÿ0-9])sem[ \\t]+)(?:erro|falha|problemas?)[ \\t]+(?:\\d{3}|no|na|ao|em|com|de|do|da|para|pra)(?![A-Za-zÀ-ÿ0-9])|n[aã]o[ \\t]+(?:(?:estou|t[oô]|to|estava|tava)[ \\t]+)?(?:consigo|consegui|conseguindo|deu[ \\t]+pra|d[aá][ \\t]+pra)[ \\t]+${OPT_CLITIC_PRONOUN}(?:abrir|carregar|escanear|ler|copiar|acessar|pagar|fazer|mandar|enviar|passar|transferir|depositar|quitar)|(?:link|qr(?:[ \\t]*code)?|c[oó]digo|chave)(?:[ \\t]+(?:d[eo][ \\t]+)?(?:pix|pagamento|cobran[cç]a|r\\$|\\d[\\d.,]*)){0,4}[ \\t]+(?:n[aã]o[ \\t]+(?:abre|abriu|carrega|carregou|funciona|funcionou|est[aá][ \\t]+funcionando|t[aá][ \\t]+funcionando|l[eê]|escaneia|entra)|(?:(?:est[aá]|t[aá]|fica|ficou|continua)[ \\t]+)?(?:dando|aparecendo|acusando)[ \\t]+(?:como[ \\t]+)?(?:inv[aá]lid[oa]|erro|falha|quebrad[oa]|expirad[oa]|vencid[oa]|indispon[ií]vel|inexistente)|(?:deu|est[aá]|t[aá]|fica|ficou|aparece|apareceu|consta|diz)[ \\t]+(?:como[ \\t]+)?(?:inv[aá]lid[oa]|quebrad[oa]|expirad[oa]|vencid[oa]|indispon[ií]vel|inexistente)|inv[aá]lid[oa]|expirou|venceu)|${EXPIRED_CHARGE_REPORT_CLAUSE}|(?:tentei|tentando)[ \\t]+${OPT_CLITIC_PRONOUN}(?:pagar|fazer|mandar|enviar|passar|transferir|depositar|gerar|abrir|quitar)|(?:app|aplicativo|banco|tela|site)[ \\t]+(?:travou|travando|fechou|caiu|bugou|parou)|em[ \\t]+duplicidade|duplicad[oa]s?|(?:cobrou|cobraram|(?:foi|foram)[ \\t]+(?:cobrad[oa]s?|pag[oa]s?|feit[oa]s?|enviad[oa]s?|transferid[oa]s?|debitad[oa]s?|descontad[oa]s?)|debitou|debitaram|descontou|descontaram|paguei|pagou|pagaram|quitei|depositei|fiz|efetuei|realizei|passou|saiu|sa[ií]ram|caiu|entrou|transferi|transferiu|enviei|enviou|mandei|mandou)(?:[ \\t]+(?:os?|as?|um|uma|esse|essa|meu|minha|me|te|lhe|d[eo]s?|da|no|na|pro|pra|r\\$|\\d[\\d.,]*|reais|real|contos?|pilas?|valor|dinheiro|pagamento|pix|cobran[cç]a)){0,6}[ \\t]+(?:[2-9]|\\d{2,})[ \\t]*(?:vezes|x)|falhou|falhando|recusou|recusaram|recusad[oa]s?|recusando|negou|negaram|negad[oa]s?|negando|rejeitou|rejeitaram|rejeitad[oa]s?|rejeitando|bloqueou|bloquearam|bloquead[oa]s?|bloqueando|barrou|barraram|barrad[oa]s?|barrando|cancelou|cancelaram|cancelad[oa]s?|cancelando|${NEGATED_SETTLEMENT_STATUS_CORE}|${OPT_CLITIC_PRONOUN}(?:mandei|enviei|fiz|efetuei|realizei|transferi|passei|depositei|paguei|quitei)(?:[ \\t]+(?:os?|as?|um|uma|esse|essa|meu|minha|d[eo]s?|da|no|na|pro|pra|via|a[ \\t]+mais|a[ \\t]+menos|repetid[oa]s?|dobrado|r\\$|\\d[\\d.,]*|reais|real|contos?|pilas?|valor|dinheiro|pagamento|pix|cobran[cç]a|transfer[eê]ncia|dep[oó]sito)){0,8}[ \\t]+(?:errad[oa]|por[ \\t]+engano|sem[ \\t]+querer|repetid[oa]s?|dobrado)|${OPT_CLITIC_PRONOUN}(?:mandei|enviei|fiz|efetuei|realizei|transferi|passei|depositei|paguei|quitei)(?:[ \\t]+(?:os?|as?|r\\$|\\d[\\d.,]*|reais|real|contos?|pilas?)){1,3}[ \\t]+a[ \\t]+mais|saldo[ \\t]+insuficiente|sem[ \\t]+saldo|(?:estourou|atingiu|bateu|excedeu|ultrapassou)[ \\t]+(?:o[ \\t]+|meu[ \\t]+)?limite|limite[ \\t]+(?:excedido|insuficiente|di[aá]rio|noturno)|(?:(?:ficou|est[aá]|t[aá]|caiu|entrou|foi|continua|ainda[ \\t]+est[aá]|ainda[ \\t]+t[aá])[ \\t]+)?(?:em|na|sob)[ \\t]+(?:an[aá]lise|processamento)|analisando|(?:(?:pix|pagamento|transfer[eê]ncia|valor)[ \\t]+pendente|(?:ficou|est[aá]|t[aá]|continua|aparece|consta)[ \\t]+pendente)|retid[oa]s?|reteve|retiveram|retendo|reten[cç][aã]o|segurou|seguraram|segurando|travou|travando|fora[ \\t]+do[ \\t]+ar|agendei|agendad[oa]s?|agendamento|estorno|estornar|estornou|estornaram|estornad[oa]s?|estornando|reembolso|reembolsar|reembolsou|reembolsaram|reembolsad[oa]s?|reembolsando|devolv(?:er|a|e|eu|eram|endo|id[oa]s?)|devolu[cç][aã]o|${FINANCIAL_RETURNED_REPORT_CLAUSE})(?![A-Za-zÀ-ÿ0-9])`,
  'i'
);

const HAS_PAYMENT_OR_BANK_CONTEXT_RE =
  /(?<![A-Za-zÀ-ÿ0-9])(?:pix|depix|pagar|pago|paguei|pagamento|cobran[cç]a|transfer[eê]ncia|transferi|transferir|dep[oó]sito|depositei|depositar|transa[cç][aã]o|comprovante|recibo|valor|reais|real|brl|contos?|pilas?|r\$|banco|conta|saldo|limite|app|aplicativo|link|qr|chave|c[oó]digo|estorn[oa]|reembols[oa]|devolu[cç][aã]o|nubank|inter|ita[uú]|bradesco|santander|caixa|bb|sicredi|sicoob|picpay|mercadopago|c6|pagbank)(?![A-Za-zÀ-ÿ0-9])/i;

const UNAMBIGUOUS_FINANCIAL_FAILURE_OR_REFUND_RE = new RegExp(
  `(?<![A-Za-zÀ-ÿ0-9])(?:(?:link|qr(?:[ \\t]*code)?|c[oó]digo|chave)(?:[ \\t]+(?:d[eo][ \\t]+)?(?:pix|pagamento|cobran[cç]a|r\\$|\\d[\\d.,]*)){0,4}[ \\t]+(?:n[aã]o[ \\t]+(?:abre|abriu|carrega|carregou|funciona|funcionou|est[aá][ \\t]+funcionando|t[aá][ \\t]+funcionando|l[eê]|escaneia|entra)|(?:(?:est[aá]|t[aá]|fica|ficou|continua)[ \\t]+)?(?:dando|aparecendo|acusando)[ \\t]+(?:como[ \\t]+)?(?:inv[aá]lid[oa]|erro|falha|quebrad[oa]|expirad[oa]|vencid[oa]|indispon[ií]vel|inexistente)|(?:deu|est[aá]|t[aá]|fica|ficou|aparece|apareceu|consta|diz)[ \\t]+(?:como[ \\t]+)?(?:inv[aá]lid[oa]|quebrad[oa]|expirad[oa]|vencid[oa]|indispon[ií]vel|inexistente)|inv[aá]lid[oa]|expirou|venceu)|${EXPIRED_CHARGE_REPORT_CLAUSE}|(?:tentei|tentando)[ \\t]+${OPT_CLITIC_PRONOUN}(?:pagar|quitar|transferir|depositar)|(?:app|aplicativo|banco)[ \\t]+(?:travou|travando|fechou|caiu|bugou|parou)|em[ \\t]+duplicidade|(?:cobrou|cobraram|(?:foi|foram)[ \\t]+(?:cobrad[oa]s?|pag[oa]s?|feit[oa]s?)|debitou|debitaram|descontou|descontaram|paguei|pagou|fiz|efetuei|realizei)(?:[ \\t]+(?:os?|as?|um|uma|esse|essa|meu|minha|me|te|lhe|d[eo]s?|da|no|na|pro|pra|r\\$|\\d[\\d.,]*|reais|real|contos?|pilas?|valor|dinheiro|pagamento|pix|cobran[cç]a)){0,6}[ \\t]+(?:[2-9]|\\d{2,})[ \\t]*(?:vezes|x)|n[aã]o[ \\t]+(?:j[aá][ \\t]+)?(?:compensou|compensaram|creditou|creditaram|autorizou|autorizaram|efetivou|liquidou|(?:foi|foram|est[aá]|t[aá])[ \\t]+(?:compensad[oa]s?|creditad[oa]s?|autorizad[oa]s?))|(?:saldo[ \\t]+insuficiente|sem[ \\t]+saldo)(?![ \\t]+(?:no|na|do|da)[ \\t]+(?:celular|chip|vivo|claro|tim|oi|linha|internet|pacote|bilhete|vale|vr|va|cart[aã]o)(?![A-Za-zÀ-ÿ0-9]))|(?:(?:estourou|atingiu|bateu|excedeu|ultrapassou)[ \\t]+(?:o[ \\t]+|meu[ \\t]+)?limite|limite[ \\t]+(?:excedido|insuficiente|di[aá]rio|noturno))(?![ \\t]+(?:do|da|no|na|de)[ \\t]+(?:cart[aã]o|cr[eé]dito|internet|dados|franquia|velocidade)(?![A-Za-zÀ-ÿ0-9]))|retid[oa]s?|reteve|retiveram|retendo|reten[cç][aã]o|(?:estorno|estornar|estornou|estornaram|estornad[oa]s?|estornando|reembolso|reembolsar|reembolsou|reembolsaram|reembolsad[oa]s?|reembolsando|devolu[cç][aã]o)(?![ \\t]+(?:d[oa]s?|no|na)[ \\t]+(?:cart[aã]o|cr[eé]dito|fatura|ingresso|passagem|voo|hotel|amazon|shopee|mercado[ \\t]*livre|ifood|uber|shein|aliexpress)(?![A-Za-zÀ-ÿ0-9]))|${FINANCIAL_RETURNED_REPORT_CLAUSE})(?![A-Za-zÀ-ÿ0-9])`,
  'i'
);

const EXPLICIT_NEW_ORDER_TARGET_TAIL =
  '(?![ \\t]+(?:a[ií][ \\t]+|aqui[ \\t]+)?(?:o[ \\t]+|a[ \\t]+|meu[ \\t]+|minha[ \\t]+|um[ \\t]+|uma[ \\t]+|esse[ \\t]+|essa[ \\t]+)?(?:comprovante|recibo|status|confirma[cç][aã]o|estorno|reembolso|devolu[cç][aã]o)(?![A-Za-zÀ-ÿ0-9]))[ \\t]+(?:(?:a[ií][ \\t]+|aqui[ \\t]+|agora[ \\t]+)?(?:(?:um[ \\t]+|uma[ \\t]+)?(?:outro|outra|novo|nova)|mais[ \\t]+um[a]?|(?:um|uma)[ \\t]+de[ \\t]+(?:r\\$[ \\t]*\\d|\\d))|(?:a[ií][ \\t]+|aqui[ \\t]+|agora[ \\t]+)?(?:um[ \\t]+|o[ \\t]+)?pix(?![A-Za-zÀ-ÿ0-9])|(?:uma[ \\t]+|a[ \\t]+)?cobran[cç]a(?![A-Za-zÀ-ÿ0-9])|(?:de[ \\t]+)?(?:r\\$[ \\t]*\\d[\\d.,]*(?![\\d.,])|\\d[\\d.,]*(?![\\d.,])[ \\t]*(?:reais|real|contos?|pilas?|mil|no[ \\t]+pix)(?![A-Za-zÀ-ÿ0-9])|mil(?![A-Za-zÀ-ÿ0-9])))';

const EXPLICIT_NEW_ORDER_INTENT_RE = new RegExp(
  `(?:(?<!(?<![A-Za-zÀ-ÿ0-9])(?:n[aã]o|nem|se|caso|quando|ele|ela|m[aã]e|pai|irm[aã]o?|espos[oa]|marido|mulher|filh[oa]|chefe|s[oó]ci[oa])[ \\t]+|(?<![A-Za-zÀ-ÿ0-9])n[aã]o[ \\t]+(?:quero|vou|posso|consigo|conseguir|poder|preciso|precisa|vai)[ \\t]+)(?<![A-Za-zÀ-ÿ0-9])(?:quero|queria|gostaria[ \\t]+de|gera|gere|mand[ae]|envi[ae]|pass[ae]|cobr[ae]|preciso(?:[ \\t]+de)?|faz|fa[cç]a|cria|cri[ae])|(?:^|[,;:!?.-][ \\t]*|(?<![A-Za-zÀ-ÿ0-9])(?:e|mas|ent[aã]o|agora|favor|por[ \\t]+favor)[ \\t]+)(?:gerar|mandar|enviar|passar|cobrar|fazer|criar))${EXPLICIT_NEW_ORDER_TARGET_TAIL}`,
  'i'
);

const POLITE_NEW_ORDER_MODAL_RE =
  /(?<!(?<![A-Za-zÀ-ÿ0-9])(?:acabei|terminei|consegui|tentei|desisti|esquece|deixa|parei)[ \t]+(?:de[ \t]+)?|(?<![A-Za-zÀ-ÿ0-9])(?:n[aã]o|nem|se|caso|quando)[ \t]+|(?<![A-Za-zÀ-ÿ0-9])(?:se|caso|quando)[ \t]+(?:eu|voc[eê]|vc|a[ \t]+gente|ele|ela)[ \t]+)(?<![A-Za-zÀ-ÿ0-9])(?:quero|queria|preciso(?:[ \t]+de)?|vou|posso|pode|poderia|gostaria[ \t]+de|me)[ \t]+(?:pagar|fazer[ \t]+(?:(?:um[ \t]+)?(?:novo[ \t]+|outro[ \t]+)?pix|(?:uma[ \t]+)?(?:nova[ \t]+|outra[ \t]+)?cobran[cç]a)|(?:gerar|mandar|mand[ae]|passar|pass[ae]|enviar|envi[ae]|criar|cri[ae]|cobrar|cobr[ae])[ \t]+(?:a[ií][ \t]+|aqui[ \t]+|agora[ \t]+)?(?:(?:um[ \t]+|uma[ \t]+)?(?:outro|outra|novo|nova)|mais[ \t]+um[a]?|(?:um|uma)[ \t]+de[ \t]+(?:r\$[ \t]*\d|\d)|(?:um[ \t]+|uma[ \t]+|o[ \t]+|a[ \t]+)?(?:pix|cobran[cç]a|link|qr(?:[ \t]*code)?|chave)|(?:de[ \t]+)?(?:r\$[ \t]*\d|\d+[ \t]*(?:reais|real|contos?|pilas?|mil|no[ \t]+pix)(?![A-Za-zÀ-ÿ0-9])|mil(?![A-Za-zÀ-ÿ0-9]))))(?![A-Za-zÀ-ÿ0-9])/i;

const FEE_OR_LIMIT_OR_PRICE_INQUIRY_RE =
  /(?<![A-Za-zÀ-ÿ0-9])(?:(?:(?:por|em|a|de)[ \t]+)?quanto[ \t]+(?:que[ \t]+)?(?:[eé]|s[aã]o|fica|ficou|custa|custou|t[aá]|est[aá]|sai|saiu|d[aá]|deu|seria|seriam|cobra|vale|faz|faria)|(?:[eé]|s[aã]o|fica|ficou|custa|custou|t[aá]|est[aá]|sai|saiu|d[aá]|deu|seria|cobra|vale|faz|fecha|deixa|cai)(?:[ \t]+(?:por|em|a|de|pra|para))?[ \t]+quanto(?![A-Za-zÀ-ÿ0-9])|qual(?:[ \t]+que)?(?:[ \t]+(?:[eé]|seria|fica|ficou))?[ \t]+(?:o[ \t]+|a[ \t]+)?(?:pre[cç]o|valor|custo|total)|(?:(?:quero|queria|gostaria[ \t]+de|preciso)[ \t]+saber|(?:pode|poderia|consegue|sabe)[ \t]+(?:me[ \t]+)?(?:dizer|falar|confirmar|informar)|me[ \t]+(?:diz|diga|fala|fale|confirma|confirme|informa|informe))[ \t]+(?:se|quanto|qual)(?![A-Za-zÀ-ÿ0-9])|(?:a[ \t]+partir[ \t]+de|acima[ \t]+de|abaixo[ \t]+de|menor[ \t]+que|maior[ \t]+que)[ \t]+(?:r\$[ \t]*)?\d|(?:tem|ter[aá]|teria|cobra|cobram|existe|ganha|ganho|tenho|recebo|consigo|consegue|d[aá]|d[aã]o|faz|fazem|rol[ae]|pago|paga|qual(?:[ \t]+que)?(?:[ \t]+[eé])?(?:[ \t]+o|[ \t]+a)?)[ \t]+(?:algum[a]?[ \t]+|um[ \t]+|uma[ \t]+)?(?:taxa|tarifa|juros?|multa|desconto|abatimento|acr[eé]scimo|encargos?|cashback)(?![A-Za-zÀ-ÿ0-9])|(?:tem|ter[aá]|teria|preciso[ \t]+de|precisa[ \t]+de|volta|voltar|dar|d[aá]|mandar|manda|levar|leva|trazer|traz|com|sem|pro|para[ \t]+o)[ \t]+troco(?![A-Za-zÀ-ÿ0-9])|troco[ \t]+(?:pra|para|de|em)(?![A-Za-zÀ-ÿ0-9])|parcel(?:ar|a|am|ado|amento)(?![A-Za-zÀ-ÿ0-9])|pix[ \t]+(?:parcelado|cr[eé]dito|troco|saque)(?![A-Za-zÀ-ÿ0-9])|(?:metade|parte|restante|resto)[ \t]+(?:no|na|em|via|pelo|pela)[ \t]+(?:cart[aã]o|cr[eé]dito|d[eé]bito|dinheiro|esp[eé]cie|boleto)(?![A-Za-zÀ-ÿ0-9])|(?:no|na|pelo|pela)[ \t]+(?:meu[ \t]+)?(?:cart[aã]o|cr[eé]dito|d[eé]bito|dinheiro|esp[eé]cie)[ \t]+e[ \t]+(?:(?:o[ \t]+)?(?:resto|restante|outra[ \t]+parte|metade)|(?:r\$[ \t]*)?\d[\d.,]*)[ \t]*(?:reais|real|contos?|pilas?)?[ \t]*(?:no|via|em|de)[ \t]+pix(?![A-Za-zÀ-ÿ0-9])|(?:cart[aã]o(?:[ \t]+de[ \t]+(?:cr[eé]dito|d[eé]bito))?|cr[eé]dito|d[eé]bito|boleto)[ \t]+ou[ \t]+(?:(?:no|via|s[oó])[ \t]+)?pix(?![A-Za-zÀ-ÿ0-9])|pix[ \t]+ou[ \t]+(?:no[ \t]+)?(?:cart[aã]o|cr[eé]dito|d[eé]bito|boleto)(?![A-Za-zÀ-ÿ0-9]))/i;

function isDirectPriceOrFeeQuestion(t: string, hasExplicitNewOrder: boolean): boolean {
  if (FEE_OR_LIMIT_OR_PRICE_INQUIRY_RE.test(t)) return true;
  if (
    (!hasExplicitNewOrder || t.endsWith('?')) &&
    /(?<![A-Za-zÀ-ÿ0-9])(?:limite|m[ií]nimo|m[aá]ximo)(?![A-Za-zÀ-ÿ0-9])/i.test(t)
  ) {
    return true;
  }
  if (!t.endsWith('?')) return false;
  if (
    /(?<![A-Za-zÀ-ÿ0-9])(?:cart[aã]o|cr[eé]dito|d[eé]bito|boleto|maquininha)(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    )
  ) {
    return true;
  }
  return /(?<![A-Za-zÀ-ÿ0-9])(?:custa|custou|fica(?:[ \t]+(?:por|em|pra|para|a))?|ficou(?:[ \t]+(?:por|em|pra|para|a))?|sai(?:[ \t]+(?:por|em|pra|para|a))?|saiu(?:[ \t]+(?:por|em|pra|para|a))?|cai(?:[ \t]+(?:por|pra|para|em|a))?|deu|(?:t[aá]|est[aá]|estava|tava)(?:[ \t]+(?:por|em|custando|saindo))?|(?:(?:o[ \t]+)?(?:pre[cç]o|valor|total)[ \t]+)?(?:[eé]|s[aã]o|seria|seriam|ficou|deu)(?:[ \t]+(?:mesmo|ent[aã]o|a[ií]|tudo|isso))?|(?:(?:d[aá][ \t]+pra|consegue|poderia|pode)[ \t]+)?(?:abaixa|abaixar|baixa|baixar|reduz|reduzir|diminui|diminuir|tira|tirar|abate|abater)(?:[ \t]+(?:pra|para|por|em|a|uns?|mais))?|(?:(?:d[aá][ \t]+pra|consegue|poderia|pode)[ \t]+)?(?:faz|fazer|faria|fecha|fechar|deixa|deixar)(?:(?:[ \t]+(?!pix(?![A-Za-zÀ-ÿ0-9])|cobran[cç]a(?![A-Za-zÀ-ÿ0-9]))[A-Za-zÀ-ÿ0-9]+){0,4}[ \t]+(?:por|a|em|pra|para|nos?|nas?)|(?=[ \t]*(?:r\$[ \t]*)?\d)))[ \t]*(?:r\$[ \t]*)?\d/i.test(
    t
  );
}

const REPLACEMENT_ORDER_INTENT_RE =
  /(?<![A-Za-zÀ-ÿ0-9])(?:(?:e|mas|ent[aã]o|agora)[ \t]+(?:quero[ \t]+|preciso[ \t]+|pode[ \t]+|me[ \t]+)?(?:gerar|gera|gere|fazer|faz|fa[cç]a|criar|cri[ae]|mandar|mand[ae]|enviar|envi[ae]|passar|pass[ae]|cobrar|cobr[ae])(?![ \t]+(?:depois|amanh[aã]))(?![A-Za-zÀ-ÿ0-9])|(?:quero[ \t]+|preciso[ \t]+|pode[ \t]+|vamos[ \t]+)?(?:trocar|troca|mudar|muda|substituir|alterar)(?:[ \t]+(?:o[ \t]+valor|esse|aquele))?[ \t]+(?:para|pra|por|em|de)[ \t]+(?:r\$[ \t]*)?\d)/i;

const TRAILING_POLITE_PIX_REQUEST_RE =
  /(?:^|[,;:.!?][ \t]+)(?:me[ \t]+)?(?:pix|cobran[cç]a)[ \t]+de[ \t]+(?:r\$[ \t]*)?\d[\d.,]*(?![\d.,])(?:[ \t]*(?:reais|real|pilas?))?[ \t]+(?:por[ \t]+favor|pfv?|pf)[ \t.!]*$/i;

function hasExplicitOrReplacementNewOrder(t: string): boolean {
  if (OUTGOING_PAYOUT_OR_DEBT_RE.test(t)) return false;
  return (
    EXPLICIT_NEW_ORDER_INTENT_RE.test(t) ||
    POLITE_NEW_ORDER_MODAL_RE.test(t) ||
    REPLACEMENT_ORDER_INTENT_RE.test(t) ||
    TRAILING_POLITE_PIX_REQUEST_RE.test(t)
  );
}

function stripDatesAndHours(input: string): string {
  return input
    .replace(/(?<!\d)(?:\d{4}\/\d{1,2}\/\d{1,2}|\d{1,2}\/\d{1,2}(?:\/\d{2,4})?)(?!\d)/g, ' ')
    .replace(/(?<!\d)(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}-\d{1,2}-\d{2,4})(?!\d)/g, ' ')
    .replace(
      /(?<![\d.,])\d{1,2}:\d{2}(?::\d{2})?(?:[ \t]*(?:a\.m\.|p\.m\.|(?:am|pm|h|hs|hr|hrs|horas?|min|mins|minutos?)(?![A-Za-zÀ-ÿ0-9])))?(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    .replace(
      /(?<![\d.,])(?:0?[1-9]|1[0-2])[ \t]*(?:a\.m\.|p\.m\.|(?:am|pm)(?![A-Za-zÀ-ÿ0-9]))/gi,
      ' '
    )
    .replace(
      /(?<![\d.,])\d{1,2}(?:[.,]\d+)?[ \t]*(?:h|hs|hr|hrs)(?:[ \t]*[0-5]\d(?![.,]\d|[ \t]*(?:reais|real|brl|contos?|pilas?|centavos?)(?![A-Za-zÀ-ÿ0-9]))(?:[ \t]*min(?:utos?)?)?)?(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    .replace(
      /(?<![\d.,])(?:[0-5]?\d)(?:[ \t]*min(?:utos?)?)?[ \t]+(?:pras|para[ \t]+as|(?:para[ \t]+a|pra[ \t]+a|para|pra)(?=[ \t]+(?:0?1(?![.,\d])|meia[ \t-]+noite))|(?:pro|para[ \t]+o|pra)(?=[ \t]+meio[ \t-]+dia))[ \t]+(?:[01]?\d|2[0-4]|meio[ \t-]+dia|meia[ \t-]+noite)(?![A-Za-zÀ-ÿ0-9])(?:[ \t]+da[ \t]+(?:manh[aã]|tarde|noite|madrugada)(?![A-Za-zÀ-ÿ0-9]))?/gi,
      ' '
    )
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])(?:(?:ao|[aà])[ \t]+)?(?:meio[ \t-]+dia|meia[ \t-]+noite)(?:[ \t]+e[ \t]+(?:meia|[0-5]?\d|uma?)(?![.,]\d|[ \t]*(?:reais|real|brl|contos?|pilas?|centavos?)(?![A-Za-zÀ-ÿ0-9]))(?:[ \t]*min(?:utos?)?)?)?(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])(?:(?:at[eé]|l[aá])[ \t]+)?(?:(?:[aà]s|pelas|das|pras|umas)[ \t]+(?:[01]?\d|2[0-4])|(?<!\d[ \t]+)[aà][ \t]+0?1)(?![.,]\d|[A-Za-zÀ-ÿ0-9]|[ \t]*(?:reais|real|brl|contos?|pilas?|centavos?)(?![A-Za-zÀ-ÿ0-9]))(?:[ \t]+e[ \t]+(?:meia(?![A-Za-zÀ-ÿ0-9])|[0-5]?\d(?![A-Za-zÀ-ÿ0-9]))(?:[ \t]*min(?:utos?)?(?![A-Za-zÀ-ÿ0-9]))?)?(?:[ \t]+da[ \t]+(?:manh[aã]|tarde|noite|madrugada)(?![A-Za-zÀ-ÿ0-9]))?/gi,
      ' '
    )
    .replace(
      /(?<![\d.,])(?:[01]?\d|2[0-4])(?:[ \t]+e[ \t]+(?:meia|[0-5]?\d)(?:[ \t]*min(?:utos?)?)?)?[ \t]+da[ \t]+(?:manh[aã]|tarde|noite|madrugada)(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    .replace(
      /(?<![\d.,])(?:[01]?\d|2[0-4])[ \t]+e[ \t]+meia(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    .replace(
      /(?<![\d.,])(?:[01]?\d|2[0-3])[ \t]+e[ \t]+[0-5]\d(?=[ \t]+(?:eu[ \t]+)?(?:fa[cç]o|mando|envio|pago|passo|transfiro|deposito|vou)(?![A-Za-zÀ-ÿ0-9]))/gi,
      ' '
    )
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])(?:dia[ \t]+)?(?:[0-2]?\d|3[01])(?:[º°])?[ \t]+de[ \t]+(?:janeiro|fevereiro|mar[cç]o|abril|maio|junho|julho|agosto|setembro|outubro|novembro|dezembro|jan|fev|mar|abr|mai|jun|jul|ago|set|out|nov|dez)(?:[ \t]+de[ \t]+\d{2,4})?(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    .replace(
      /(?<!(?<![A-Za-zÀ-ÿ0-9])bom[ \t]+)(?<![A-Za-zÀ-ÿ0-9])dia[ \t]+(?:[0-2]?\d|3[01])(?![.,]\d|\d|[A-Za-zÀ-ÿ]|[ \t]*(?:reais|real|brl|contos?|pilas?|centavos?)(?![A-Za-zÀ-ÿ0-9]))/gi,
      ' '
    );
}

export function hasPixTriggerKeyword(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN * 2) return false;
  const norm = normalizeHorizontalSpaces(text);
  if (norm.length > MAX_NLU_LEN) return false;
  return /(?<![A-Za-zÀ-ÿ0-9])(?:pix|depix|pagar|pagamento|comprovante)(?![A-Za-zÀ-ÿ0-9])/i.test(
    norm
  );
}

export function parseBrlAmountFromText(text: string): number | null {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN * 2) return null;
  // Remove payloads EMVCo BRCode Pix Copia e Cola ("000201...br.gov.bcb.pix...6304XXXX") e emojis decorativos antes do split por espaço!
  const cleaned = stripDecorativeEmojis(normalizeHorizontalSpaces(text))
    .replace(/(?<![A-Za-zÀ-ÿ0-9])000201[A-Za-z0-9.*+\-/_@ $:]{15,400}6304[0-9A-Fa-f]{4}(?![A-Za-zÀ-ÿ0-9])/g, ' ')
    .trim();
  if (!cleaned || cleaned.length > MAX_NLU_LEN) return null;

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

  // Remove formatação Markdown pareada do WhatsApp (*50,00*, _50,00_, ~50~), desenrola citações pareadas ("pix de 50") sem afetar polegadas (27") e separa "50reais"/"50pila"/"50R$"
  const unformattedWords = unwrapWhatsAppMarkdown(filteredWords)
    .replace(/(^|[\s([{:=-])"([^"\n]+)"(?=$|[\s)\]}.,!?;:])/g, '$1$2')
    .replace(/(\d)(reais|real|brl|contos?|pilas?|centavos?)(?![A-Za-zÀ-ÿ0-9])/gi, '$1 $2')
    .replace(/(\d)(r\$)/gi, '$1 $2');
  // Converte "50 R$" pós-fixado em "R$ 50" quando não for prefixo de segundo número ("50 R$ 30")
  const normalizedBrlOrder = unformattedWords.replace(
    /(?<![-\wÀ-ÿºª°@/,.])(\d[\d.,]*)[ \t]+r\$(?![ \t]*\d)/gi,
    'R$ $1'
  );

  // Rejeita vírgulas decimais malformadas (3+ dígitos após vírgula, ex: "150,555" ou "50,12345678") ANTES de limpar \d{8,}!
  if (/\d,\d{3,}/.test(normalizedBrlOrder) || hasForeignCurrencyOrCrypto(normalizedBrlOrder)) {
    return null;
  }

  const withoutContactsAndDates = normalizedBrlOrder
    // 0) Remove linhas digitáveis FEBRABAN de boletos bancários (47 dígitos) e convênios/concessionárias (48 dígitos) ANTES de sobrar o dígito verificador isolado!
    .replace(
      /(?<!\d)\d{5}\.?\d{5}[ \t]+\d{5}\.?\d{6}[ \t]+\d{5}\.?\d{6}[ \t]+\d[ \t]+\d{14}(?!\d)/g,
      ' '
    )
    .replace(/(?<!\d)(?:\d{11}[ \t-]+\d[ \t]*){4}(?!\d)/g, ' ')
    .replace(/(?<!\d)\d{12}[ \t]+\d{12}[ \t]+\d{12}[ \t]+\d{12}(?!\d)/g, ' ')
    // 1) Remove documentos estruturados (CPF, CNPJ numérico ou alfanumérico, CEP pontuado, RG — com hífen OU espaço antes do DV) e datas ANTES de pares hifenizados!
    .replace(
      /(?<![A-Za-z0-9])[A-Za-z0-9]{2}\.[A-Za-z0-9]{3}\.[A-Za-z0-9]{3}\/[A-Za-z0-9]{4}[ \t-]\d{2}(?![.,]\d|\d)/g,
      ' '
    )
    .replace(/(?<!\d)\d{3}\.\d{3}\.\d{3}[ \t-]\d{2}(?![.,]\d|\d)/g, ' ')
    .replace(/(?<!\d)\d{2}\.\d{3}[ \t-]\d{3}(?![.,]\d|\d)/g, ' ')
    .replace(/(?<!\d)\d{1,2}\.\d{3}\.\d{3}[ \t-][\dxX](?![A-Za-zÀ-ÿ0-9])/g, ' ')
    .replace(/(?<!\d)(?:\d{4}\/\d{1,2}\/\d{1,2}|\d{1,2}\/\d{1,2}(?:\/\d{2,4})?)(?!\d)/g, ' ')
    .replace(/(?<!\d)(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}-\d{1,2}-\d{2,4})(?!\d)/g, ' ')
    .replace(/(?<!\d[.,]|\d)\d+(?:-\d+){2,}(?![.,]\d|\d)/g, ' ')
    // 2) Remove telefones completos COM ou SEM parênteses, DDD, espaço após o 9º dígito, pontos ou fixos 8 dígitos ("3333 3333")
    .replace(
      /(?<![\d.,])(?:(?:\+\d{1,3}[ \t]*|(?<![A-Za-zÀ-ÿ0-9])55[ \t]+))?(?:\(0?\d{2}\)[ \t]*|(?<![A-Za-zÀ-ÿ0-9])0?\d{2}[ \t]*)(?:9[-.\s]?)?\d{4}[-.\s]?\d{4}(?![.,]\d|\d)/g,
      ' '
    )
    .replace(/(?<![\d.,])(?:9[-.\s]?)?\d{4}[-.]\d{4}(?![.,]\d|\d)/g, ' ')
    .replace(/(?<![\d.,A-Za-zÀ-ÿ])[2-5]\d{3}[ \t]+\d{4}(?![.,]\d|[A-Za-zÀ-ÿ0-9])/g, ' ')
    // 3) Remove CEPs simples e contas hifenizadas (preservando pontuação final ", "/"."; NUNCA apaga \d{8,} solto para não burlar a trava de token único!)
    .replace(/(?<!\d[.,]|[\d/-])\d+-\d+(?![.,]\d|[\d/-])/g, ' ');

  // Converte numerais cardinais em português ("dois mil", "dez e cinquenta", "quatro da tarde") ANTES de limpar horas/datas!
  const withNormalizedPtNumbers = stripDatesAndHours(
    normalizePortugueseNumberWords(withoutContactsAndDates)
  );

  // Rejeita moedas estrangeiras/cripto mesmo após normalizar numerais por extenso ("cinquenta dólares", "cem USDT", "US$ cinquenta")
  if (hasForeignCurrencyOrCrypto(withNormalizedPtNumbers)) {
    return null;
  }

  // Rejeita intenções negadas, ofertas condicionais de pechincha, posse negativa ou relatos de erro/estorno sem pedido independente de substituição
  const hasReplacementVerb =
    REPLACEMENT_ORDER_INTENT_RE.test(withNormalizedPtNumbers) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:trocar|troca|mudar|muda|substituir|alterar|nov[oa]|outr[oa])(?![A-Za-zÀ-ÿ0-9])/i.test(
      withNormalizedPtNumbers
    );
  const hasExplicitNewOrderIntent = hasExplicitOrReplacementNewOrder(withNormalizedPtNumbers);

  // Dúvidas de preço, taxa, desconto, acréscimo, juros, limite ou valor mínimo/máximo nunca emitem cobrança Pix
  if (isDirectPriceOrFeeQuestion(withNormalizedPtNumbers, hasExplicitNewOrderIntent)) {
    return null;
  }

  // Ofertas condicionais de negociação ("Se fizer por 50 eu pago no pix") e pedidos de transferência sainte para conta/chave do cliente nunca geram cobrança
  if (
    OUTGOING_PAYOUT_OR_DEBT_RE.test(withNormalizedPtNumbers) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:se|caso)[ \t]+(?:voc[eê][ \t]+|vc[ \t]+|tu[ \t]+)?(?:fizer|fa[cç]a|for(?=[ \t]+(?:por[ \t]+|de[ \t]+|a[ \t]+|uns?[ \t]+)?(?:r\$[ \t]*)?\d)|ficar|fique|sair|saia|deixar|deixe|fechar|feche|abaixar|baixar|tirar|custar|aceitar|topar|der[ \t]+por)(?![A-Za-zÀ-ÿ0-9])/i.test(
      withNormalizedPtNumbers
    )
  ) {
    return null;
  }

  if (
    /(?<![A-Za-zÀ-ÿ0-9])n[aã]o(?:[ \t]+(?:quero|vou|posso|consigo|consegui|conseguir|conseguindo|poder|podendo|preciso|precisa|estou|t[oô]|to|estava|tava|fiquei|foi|poss[ií]vel|deixou|deixaram|deixa|liberou|permitiu|deu|vai|dar|mais|de|do|da|para|pra|agora|hoje|te|lhe|lhes)){1,6}[ \t]+(?:pagar|fazer|gerar|mandar|enviar|transferir|passar|depositar|quitar|(?:o[ \t]+|os[ \t]+|um[ \t]+)?pix(?![A-Za-zÀ-ÿ0-9])|r\$|\d)/i.test(
      withNormalizedPtNumbers
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:n[aã]o[ \t]+(?:tenho|tinha|terei|(?:estou|t[oô]|to|estava|tava)[ \t]+com)|(?:estou|t[oô]|to|estava|tava|fiquei)[ \t]+sem|sem[ \t]+ter)(?:[ \t]+(?:mais|aqui|agora|hoje|os?|as?|esses?|essas?|aqueles?|aquelas?|o[ \t]+valor[ \t]+de|dinheiro[ \t]+(?:para|pra|pro|do)|grana[ \t]+(?:para|pra|pro|do))){0,3}[ \t]+(?:(?:o[ \t]+|um[ \t]+)?pix[ \t]+de[ \t]+)?(?:r\$[ \t]*)?\d/i.test(
      withNormalizedPtNumbers
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])n[aã]o[ \t]+(?:(?:te|lhe|lhes)[ \t]+)?(?:gera|gerar|mand[ae]|mandar|faz|fazer|envi[ae]|enviar|pagar|transferir|passar)(?![A-Za-zÀ-ÿ0-9])/i.test(
      withNormalizedPtNumbers
    ) ||
    (!hasReplacementVerb &&
      !hasExplicitNewOrderIntent &&
      /(?<![A-Za-zÀ-ÿ0-9])(?:cancel(?:ar|a|e)|esquece|esque[cç]a|desisto|desisti|deixa[ \t]+(?:pra[ \t]+l[aá]|quieto|assim)|melhor[ \t]+n[aã]o)(?![A-Za-zÀ-ÿ0-9])/i.test(
        withNormalizedPtNumbers
      )) ||
    (!hasReplacementVerb &&
      !hasExplicitNewOrderIntent &&
      (ACCOUNT_DEBITED_REPORT_RE.test(withNormalizedPtNumbers) ||
        PAYMENT_FAILURE_OR_REFUND_RE.test(withNormalizedPtNumbers) ||
        /(?<![A-Za-zÀ-ÿ0-9])(?:paguei|quitei|depositei|conclu[ií]|finalizei|completei)(?![A-Za-zÀ-ÿ0-9])/i.test(
          withNormalizedPtNumbers
        ) ||
        /(?<![A-Za-zÀ-ÿ0-9])quase[ \t]+(?:que[ \t]+)?(?:eu[ \t]+)?(?:(?:te|lhe|lhes|me|nos)[ \t]+)?(?:fiz|paguei|quitei|depositei|mandei|enviei|passei|transferi|conclu[ií]|finalizei|completei)(?![A-Za-zÀ-ÿ0-9])/i.test(
          withNormalizedPtNumbers
        ) ||
        /(?<![A-Za-zÀ-ÿ0-9])(?:ainda[ \t]+)?n[aã]o[ \t]+(?:j[aá][ \t]+)?(?:(?:te|lhe|lhes|me|nos)[ \t]+)?(?:paguei|quitei|depositei|passei|fiz|efetuei|realizei|mandei|enviei|transferi|conclu[ií]|finalizei|completei|consegui|(?:foi|foram|est[aá]|est[aã]o|t[aá]|t[aã]o)[ \t]+pag[oa]s?)(?![A-Za-zÀ-ÿ0-9])/i.test(
          withNormalizedPtNumbers
        ) ||
        /(?<![A-Za-zÀ-ÿ0-9])(?:paguei|quitei|depositei|passei|fiz|efetuei|realizei|mandei|enviei|transferi|conclu[ií]|finalizei|completei|pag[oa]s?)[ \t]+n[aã]o(?![A-Za-zÀ-ÿ0-9])/i.test(
          withNormalizedPtNumbers
        )))
  ) {
    return null;
  }

  // Rejeita valores negativos explícitos, vírgulas malformadas ("150,555", "1,500"), centavos decimais e quantificadores vagos antes de "mil"
  if (
    /r\$[ \t]*-[ \t]*\d/i.test(withNormalizedPtNumbers) ||
    /-[ \t]*r\$[ \t]*\d/i.test(withNormalizedPtNumbers) ||
    /(?:^|[\s(/:=])-\d/.test(withNormalizedPtNumbers) ||
    /\d,\d{3,}/.test(withNormalizedPtNumbers) ||
    /\d[.,]\d+[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9])/i.test(withNormalizedPtNumbers) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:quantos?|v[aá]rios?|alguns|algumas|muitos?|poucos?|tantos?|uns|umas)[ \t]+mil(?![A-Za-zÀ-ÿ0-9])/i.test(
      withNormalizedPtNumbers
    )
  ) {
    return null;
  }

  // Rejeita expressões aritméticas (+, *, /, dividido, -, menos — inclusive após "reais") e dúvidas sobre taxas/descontos
  if (
    /(?<![-\w@/,.])(?:r\$[ \t]*)?\d[\d.,]*(?![\d.,])[ \t]*(?:reais|real|brl|contos?|pilas?|centavos?)?[ \t]*[+*×÷/][ \t]*(?:r\$[ \t]*)?\d/i.test(
      withNormalizedPtNumbers
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])dividid[oa]s?[ \t]+(?:por|em)[ \t]+\d/i.test(withNormalizedPtNumbers) ||
    /(?<![-\w@/,.])(?:r\$[ \t]*)?\d[\d.,]*(?![\d.,])[ \t]*(?:reais|real|brl|contos?|pilas?)?(?:[ \t]*-[ \t]*(?:r\$[ \t]*)?\d|[ \t]+menos[ \t]+(?:r\$[ \t]*)?\d)/i.test(
      withNormalizedPtNumbers
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:taxa|tarifa|juros?|multa|desconto|abatimento|acr[eé]scimo|encargos?|cashback)(?:[ \t]+(?:de|do|da|dos|das|no|na|nos|nas|em|num|numa|pra|para|pro|sobre|acima|abaixo|por|com|pelo|pela|pelos|pelas|gerar|gera|fazer|faz|pagar|enviar|mandar|receber|usar|o|a|os|as|um|uma|uns|umas|esse|essa|esses|essas|pix|pagamento|cobran[cç]a|valor)){1,8}[ \t]+(?:r\$[ \t]*)?\d/i.test(
      withNormalizedPtNumbers
    )
  ) {
    return null;
  }

  // Rejeita porcentagens
  if (PCT_REGEX.test(withNormalizedPtNumbers)) {
    return null;
  }

  // Passo A de sanitização: limpa logradouros, complementos de endereço ("Quadra 10 Lote 5", "Bloco 2 Sala 204", "Torre 1 Apto 502") e identificadores rotulados ANTES da checagem de multiplicadores!
  const addressAndIdSanitized = withNormalizedPtNumbers
    // Remove hashtags/códigos (#80, #150), polegadas com símbolo (27", 15,6", 17'') e "nº 50"/"número 50" autônomo
    .replace(/#[ \t]*\d+(?:[.,]\d+)?/g, ' ')
    .replace(/(?<![\d.,])\d+(?:[.,]\d+)?(?:"|''|″)/g, ' ')
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])(?:n[º°]|n[uú]mero|n[uú]m\.?)[ \t#:.-]*\d+(?:[.,]\d+)?(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    )
    // Remove logradouros com ou sem nome da via + número do imóvel ("Rua Tiradentes, 85", "Av. Paulista, 1000", "Rodovia BR-101") sem confundir "TV" ou "largo por 100"!
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])(?:(?:rua|avenida|av|travessa|alameda|rodovia|estrada|pra[cç]a|viela|beco)(?![A-Za-zÀ-ÿ0-9])|(?:av|tv|al|rod|est)\.(?![A-Za-zÀ-ÿ0-9])|largo(?=[ \t]+(?:d[oa]s?|de|s[aã]o|santa|santo|nossa)(?![A-Za-zÀ-ÿ0-9])))(?:[ \t]+(?!(?:pix|pagar|pago|pagamento|cobran[cç]a|mand[ae]|mandar|gera|gerar|faz|fazer|envi[ae]|enviar|pass[ae]|passar|cobr[ae]|cobrar|cria|criar|depositar|transferir|transfiro|quero|preciso|valor|total|reais|real|brl|contos?|pilas?|por(?=[ \t]+(?:r\$[ \t]*)?\d))(?![A-Za-zÀ-ÿ0-9]))[A-Za-zÀ-ÿ][-A-Za-zÀ-ÿ.]{0,24}(?![-A-Za-zÀ-ÿ.])){0,5}[ \t,-]*(?:n[º°o.]?[ \t]*)?\d{1,5}(?![.,]\d|\d|[A-Za-zÀ-ÿ]|[ \t]*(?:reais|real|brl|contos?|pilas?|centavos?|pix)(?![A-Za-zÀ-ÿ0-9]))/gi,
      ' '
    )
    // Remove CEP, CPF, CNPJ, RG e agência/conta mesmo quando o sufixo/dígito verificador vem separado por espaço ("cep 01310 100", "conta 12345 6", "cpf 123456789 50")
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])cep\.?(?:[ \t]+[eé](?![A-Za-zÀ-ÿ0-9]))?[ \t#:=-]*(?:\d{8}|\d{2}[ \t.]?\d{3}[ \t-]+\d{3})(?![.,]\d|\d|[A-Za-zÀ-ÿ])/gi,
      ' '
    )
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])cpf\.?(?:[ \t]+[eé](?![A-Za-zÀ-ÿ0-9]))?[ \t#:=-]*(?:\d{11}|\d{9}[ \t-]+\d{2}|\d{3}[ \t.]+\d{3}[ \t.]+\d{3}[ \t-]+\d{2})(?![.,]\d|\d|[A-Za-zÀ-ÿ])/gi,
      ' '
    )
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])cnpj\.?(?:[ \t]+[eé](?![A-Za-zÀ-ÿ0-9]))?[ \t#:=-]*(?:\d{14}|\d{12}[ \t-]+\d{2}|[A-Za-z0-9]{2}[ \t.]+[A-Za-z0-9]{3}[ \t.]+[A-Za-z0-9]{3}[ \t/]+[A-Za-z0-9]{4}[ \t-]+\d{2})(?![.,]\d|\d|[A-Za-zÀ-ÿ])/gi,
      ' '
    )
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])rg\.?(?:[ \t]+[eé](?![A-Za-zÀ-ÿ0-9]))?[ \t#:=-]*(?:\d{7,10}|\d{1,2}[ \t.]+\d{3}[ \t.]+\d{3}[ \t-]+[\dxX])(?![.,]\d|\d|[A-Za-zÀ-ÿ])/gi,
      ' '
    )
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])(?:ag[eê]ncia|ag|conta(?:[ \t]+(?:corrente|poupan[cç]a|sal[aá]rio|digital))?|poupan[cç]a|cc)\.?(?:[ \t]+[eé](?![A-Za-zÀ-ÿ0-9]))?(?:[ \t]*[:=-][ \t]*(?:#|n[º°o.]?[ \t:.=-]*)?|[ \t]+(?:#|n[º°o.]?[ \t:.=-]*)?|[ \t]*#[ \t]*)\d+(?:[ \t-]+[\dxX]{1,2}(?![.,]\d|\d|[A-Za-zÀ-ÿ]|[ \t]*(?:reais|real|brl|contos?|pilas?|centavos?|mil)(?![A-Za-zÀ-ÿ0-9])))?(?![.,]\d|\d|[A-Za-zÀ-ÿ]|[ \t]*(?:reais|real|brl|contos?|pilas?|centavos?)(?![A-Za-zÀ-ÿ0-9]))/gi,
      ' '
    )
    .replace(
      /(?<![A-Za-zÀ-ÿ0-9])(?:pedido|ordem|protocolo|chamado|fatura|boleto|nota[ \t]+fiscal|nota|nf-?e|nfs-?e|nf|danfe|comanda|cupom|senha|ficha|contrato|matr[ií]cula|or[cç]amento|reserva|erro|status[ \t]+http|http|iphone|ipad|airpods|macbook|apple[ \t]+watch|galaxy|redmi(?:[ \t]+note)?|poco|moto[ \t]+g|playstation|xbox|windows|gopro|mesa|quarto|ap|apt|apto|apartamento|rua|av|avenida|travessa|alameda|rodovia|estrada|km|bloco|bl|quadra|qd|lote|lt|torre|conjunto|cj|setor|pr[eé]dio|condom[ií]nio|cond|galp[aã]o|box|quiosque|casa|sala|loja|andar|piso|id|cod|c[oó]digo|item|op[cç][aã]o|tamanho|tam|numera[cç][aã]o|aro|calibre|bitola|modelo|mod|vers[aã]o|voltagem|tens[aã]o|pot[eê]ncia|opera[cç][aã]o|op|banco|cpf|cnpj|cep|rg)\.?(?:[ \t]+[eé](?![A-Za-zÀ-ÿ0-9]))?(?:[ \t]*[:=-][ \t]*(?:#|n[º°o.]?[ \t:.=-]*)?|[ \t]+(?:#|n[º°o.]?[ \t:.=-]*)?|[ \t]*#[ \t]*)\d+(?:[.,]\d+)?(?![.,]\d|\d|[A-Za-zÀ-ÿ]|[ \t]*(?:reais|real|brl|contos?|pilas?|centavos?)(?![A-Za-zÀ-ÿ0-9]))/gi,
      ' '
    );

  // Rejeita multiplicadores de quantidade e medidas com preço unitário ("2 itens de R$ 50", "2 kg de R$ 50", "2 pix de 50") APÓS limpar complementos de endereço ("Quadra 10 Lote 5")!
  if (
    QTY_WITH_UNIT_PRICE_RE.test(addressAndIdSanitized) ||
    /(?<![\d.,])(?:[2-9]|\d{2,})[ \t]*pix[ \t]+(?:de[ \t]+|por[ \t]+|a[ \t]+)?(?:r\$[ \t]*)?\d/i.test(
      addressAndIdSanitized
    )
  ) {
    return null;
  }

  const sanitized = addressAndIdSanitized
    // Remove contagem inteira "1 pix" / "5 pix" SEM corromper "R$ 1.500 pix" ou "50,75 pix"!
    .replace(
      /(?<!(?<![A-Za-zÀ-ÿ])r\$[ \t]*)(?<![\d.,])\d+(?![.,]\d)[ \t]+pix(?![A-Za-zÀ-ÿ0-9])/gi,
      ' pix '
    )
    // Converte milhões para escala exata (caindo no aviso de teto máximo em vez de cobrar R$ 1,00!)
    .replace(
      /(?:(?<![-\wÀ-ÿ@/,.])(\d{1,3}(?:[.,]\d{1,2})?)(?![.,]\d|\d)[ \t]*|(?<![A-Za-zÀ-ÿ0-9])(meio)[ \t]+)milh(?:[aã]o|[oõ]es)(?![A-Za-zÀ-ÿ0-9])/gi,
      (_m, nStr, halfWord) => {
        const mult = halfWord ? 0.5 : Number(String(nStr).replace(',', '.'));
        return String(Math.round(mult * 1_000_000));
      }
    )
    // Passagem única determinística para TODAS as composições com "mil" (fronteira Unicode estrita: NUNCA casa dentro de "milímetros"/"milésimos"!):
    // Aceita "[N] mil e M", "[N] mil 250", "dois mil, quinhentos", "dois mil e quinhentos e cinquenta centavos" e "mil reais" em qualquer contexto!
    .replace(
      /(?:(?<![-\wÀ-ÿºª°@/,.])(\d{1,4}(?:[.,]\d{1,2})?)(?![.,]\d|\d)[ \t]*|(?<=^|[ \t]*[:=(\-,;.!?][ \t]*|r\$[ \t]*|(?<![A-Za-zÀ-ÿ0-9])(?:de|por|para|pra|no|em|com|at[eé]|gera|gerar|gere|mand[ae]|mandar|envi[ae]|enviar|pass[ae]|passar|cobr[ae]|cobrar|faz|fa[cç]a|fazer|cria|cri[ae]|criar|quero|queria|gostaria|preciso|pagar|pago|pague|receber|depositar|transferir|cobran[cç]a|pagamento|pix|valor|total|ser|seria|[eé]|s[aã]o|fica|ficou|sai|saiu|custa|custou|fecha|fechou|deu|d[aá]|v[eê]|veja|oi|ol[aá]|opa|dia|tarde|noite|a[ií]|aqui|l[aá]|ali|ent[aã]o|agora|j[aá]|logo|hoje|favor|pfv?|amigo|amiga|chefe|mano|cara|irm[aã]o|outro|outra|novo|nova|mais)[ \t]+))mil(?![A-Za-zÀ-ÿ0-9])(?![ \t]+(?:maravilhas|desculpas|perd[oõ]es|coisas|problemas|motivos|anos[ \t]+luz)(?![A-Za-zÀ-ÿ0-9]))(?:[ \t]+(reais|real|brl|contos?|pilas?)(?![A-Za-zÀ-ÿ0-9])(?:[ \t]+e[ \t]+(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9]))?|(?:[ \t]+e[ \t]+(?:(meio)(?![A-Za-zÀ-ÿ0-9])|(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9])|(\d{1,3}(?:,\d{1,2})?)(?![.,]\d|\d|[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9]))(?:[ \t]*(reais|real|brl|contos?|pilas?)(?![A-Za-zÀ-ÿ0-9]))?(?:[ \t]+e[ \t]+(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9]))?)|(?:[ \t]*,[ \t]*|[ \t]+)(?:(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9])|([1-9]\d{2}(?:,\d{1,2})?)(?![.,]\d|\d|[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9]))(?:[ \t]*(reais|real|brl|contos?|pilas?)(?![A-Za-zÀ-ÿ0-9]))?(?:[ \t]+e[ \t]+(\d{1,2})(?![.,]\d|\d)[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9]))?))?)/gi,
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
        const addReais = halfWord
          ? 500
          : extraStr
            ? Number(String(extraStr).replace(',', '.'))
            : 0;
        const centsStr =
          unit1Cents ?? eDirectCents ?? eTailCents ?? bareDirectCents ?? bareTailCents;
        const cents = centsStr ? Number(centsStr) : 0;
        const total = Math.round((mult * 1000 + addReais + cents / 100) * 100) / 100;
        const formatted = Number.isInteger(total)
          ? String(total)
          : total.toFixed(2).replace('.', ',');
        const hasUnit = Boolean(unit1 || eUnit2 || bareUnit2 || centsStr || !Number.isInteger(addReais));
        return hasUnit ? `${formatted} reais` : formatted;
      }
    )
    // Converte "X reais/contos/pilas e meio" ("dez reais e meio" -> "R$ 10,50", "uma pila e meia" -> "R$ 1,50") e "X e meio" ("15 e meio" -> "15,50", mantendo unidades físicas como "2 e meio kg" limpas a seguir!)
    .replace(
      /(?<![-\wÀ-ÿºª°@/,.])(\d{1,3}(?:\.\d{3})+|\d{1,6})(?![.,]\d|\d)[ \t]*(?:pilas?[ \t]+e[ \t]+mei[oa]|(?:reais|real|brl|contos?)[ \t]+e[ \t]+meio)(?![A-Za-zÀ-ÿ0-9])/gi,
      (_m, r) => `R$ ${String(r).replace(/\./g, '')},50`
    )
    .replace(
      /(?<![-\wÀ-ÿºª°@/,.])(\d{1,3}(?:\.\d{3})+|\d{1,6})(?![.,]\d|\d)[ \t]+e[ \t]+meio(?![A-Za-zÀ-ÿ0-9])/gi,
      (_m, r) => `${String(r).replace(/\./g, '')},50`
    )
    // Converte "X reais e Y [centavos]" (ex: "1.500 reais e 50 centavos", "20 reais e 50") e "N centavos" isolado
    .replace(
      /(?<![-\wÀ-ÿºª°@/,.])(\d{1,3}(?:\.\d{3})+|\d{1,6})[ \t]*(?:reais|real|brl|contos?|pilas?)[ \t]+e[ \t]+(?!r\$)(\d{1,2})(?![.,]\d|\d|[ \t]*(?:reais|real|brl|contos?|pilas?|mil|milh))(?![A-Za-zÀ-ÿ0-9])(?:[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9]))?/gi,
      (_m, r, c) => `R$ ${String(r).replace(/\./g, '')},${String(c).padStart(2, '0')}`
    )
    .replace(
      /(?<![-\wÀ-ÿ@/,.])(\d{1,6})(?![.,]\d|\d)[ \t]*centavos?(?![A-Za-zÀ-ÿ0-9])/gi,
      (_m, c) => {
        const valFixed = (Number(c) / 100).toFixed(2).replace('.', ',');
        return `R$ ${valFixed}`;
      }
    )
    .replace(SUFFIX_UNIT_STRIP_RE, ' ')
    .replace(/(?<![\d.,])\d+(?:[.,]\d+)*(?![.,]\d|\d)ah(?![A-Za-zÀ-ÿ0-9])/gi, ' ')
    .replace(
      /(?<![\d.,])\d+(?:[.,]\d+)*(?![.,]\d|\d)[ \t]*(?:min|mins|minutos?|minutinhos?|seg|segs|segundos?|segundinhos?|instantes?|instantinhos?|dias?|semanas?|horas?|horinhas?|m[eê]s|meses|anos?)(?![A-Za-zÀ-ÿ0-9])/gi,
      ' '
    );

  // Rejeita moedas/criptoativos também após conversão de "mil"/"milhão" ("2 mil USDT", "5 mil satoshis")
  if (hasForeignCurrencyOrCrypto(sanitized)) {
    return null;
  }

  // Rejeita somas, subtrações e intervalos ("R$ 50 e 30", "R$ 50 mais 30", "R$ 50 - 10", "50 a 100 reais", "de 50 até 100")
  if (
    /(?<![-\w@/,.])(?:r\$[ \t]*)?\d[\d.,]*(?![\d.,])[ \t]*(?:reais|real|brl|contos?|pilas?)?[ \t]+(?:e|mais|menos|a|à|at[eé])[ \t]+(?:r\$[ \t]*)?\d/i.test(
      sanitized
    ) ||
    /(?<![-\w@/,.])(?:r\$[ \t]*)?\d[\d.,]*(?![\d.,])[ \t]*(?:reais|real|brl|contos?|pilas?)?[ \t]*-[ \t]*(?:r\$[ \t]*)?\d/i.test(
      sanitized
    )
  ) {
    return null;
  }

  // Extrai todos os candidatos numéricos livres com fronteiras estritas ANTES de parsear:
  // nunca descarta silenciosamente `0`, `>= 8` dígitos ou `> 10_000_000`, bloqueando "0 ou 50", "20.000.000 ou 50" e "123456789 50"!
  const rawTokenMatches = Array.from(sanitized.matchAll(ALL_TOKENS_REGEX));
  if (rawTokenMatches.length !== 1) {
    return null;
  }

  return parseNumericToken(rawTokenMatches[0][1]);
}

/**
 * Varredura linear O(N) com dois ponteiros — zero regex backtracking!
 */
export function normalizeCommandText(text: string): string {
  if (typeof text !== 'string' || text.length > MAX_COMMAND_LEN * 2) return '';
  const norm = stripDecorativeEmojis(normalizeHorizontalSpaces(text));
  if (norm.length > MAX_COMMAND_LEN) return '';
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
  const rawNorm = normalizeCommandText(text);
  if (!rawNorm) return false;
  const n = normalizePortugueseNumberWords(rawNorm).replace(
    /(?<![A-Za-zÀ-ÿ0-9])mil(?![A-Za-zÀ-ÿ0-9])/gi,
    '1000'
  );
  if (
    /(?<![A-Za-zÀ-ÿ0-9])(?:n[aã]o|nem|gerar|gera|gere|fazer|faz|fa[cç]a|criar|cri[ae]|trocar|troca|mudar|muda|substituir|alterar|nov[oa]|outr[oa])(?![A-Za-zÀ-ÿ0-9])/i.test(
      n
    )
  ) {
    return false;
  }
  const tailRe =
    '(?: (?:o |a |esse |essa |meu |minha )?(?:pix|cobran[cç]a|pedido|tudo|atendimento))?(?: (?:de )?(?:r\\$ ?)?\\d[\\d.,]*(?: reais| real| contos?| pilas?)?)?(?: no pix)?(?: a[ií]| aqui| ent[aã]o| logo| agora| por favor| pfv| pf)?$';
  if (
    new RegExp(
      `^(?:cancelar|cancela|cancele|reiniciar|reinicia|reinicie|reset|resetar)${tailRe}`,
      'i'
    ).test(n)
  ) {
    return true;
  }
  return new RegExp(
    `^(?:quero|pode|favor|por favor|preciso) (?:cancelar|cancela|cancele|reiniciar)${tailRe}`,
    'i'
  ).test(n);
}

export function isHelpCommand(text: string): boolean {
  const n = normalizeCommandText(text);
  if (!n) return false;
  return (
    /^(?:ajuda|help|menu|op[cç][oõ]es|instru[cç][oõ]es|comandos|como funciona|me ajuda|preciso de ajuda)$/.test(
      n
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:como (?:funciona (?:o )?(?:pix|pagamento|sistema|rob[oô]|atendimento)|fa[cç]o (?:para|pra) pagar|pagar(?: no pix)?|usar(?: o pix)?)|(?:preciso de ajuda|me ajuda) (?:com|no|na|para|pra) (?:o |a )?(?:pix|pagar|pagamento|cobran[cç]a))(?![A-Za-zÀ-ÿ0-9])/i.test(
      n
    )
  );
}

export interface ActiveMenuParseResult {
  choice: 'resend' | 'new' | 'none';
  explicitOptionDigit: '1' | '2' | null;
  inlineNewAmountBrl: number | null;
}

const MENU_CONVERSATIONAL_PREFIX_RE =
  /^(?:(?:oi|ol[aá]|opa|bom[ \t]+dia|boa[ \t]+tarde|boa[ \t]+noite|sim|ok|okay|beleza|blz|certo|combinado|fechado|perfeito|show|top|isso(?:[ \t]+mesmo)?|por[ \t]+favor|pfv?|favor|ent[aã]o|nesse[ \t]+caso)(?![A-Za-zÀ-ÿ0-9])[ \t,;.!\-]*)+/i;

const LEADING_MENU_OPT_RE =
  /^(?:(?:(?:quero|queria|escolho|prefiro|vou|vai|bora|vamos|fecha|fecho|segue|fico[ \t]+com|fica|pode[ \t]+ser|(?:(?:a|o|minha|meu)[ \t]+)?(?:op[cç][aã]o|escolha|item)[ \t]+(?:[eé]|seria)|[eé]|seria)[ \t]+)?(?:(?:(a|o|na|no|pela|pelo)|de|com)[ \t]+)?|(?:(?:pode|poderia|consegue|favor|por[ \t]+favor)[ \t]+)?(?:me[ \t]+)?(?:mand[ae]|mandar|envi[ae]|enviar|pass[ae]|passar|faz|fa[cç]a|fazer|gera|gere|gerar|cria|cri[ae]|criar)[ \t]+(?=(?:a|o|na|no|pela|pelo|op[cç][aã]o|item|n[uú]mero)(?![A-Za-zÀ-ÿ0-9]))(?:(a|o|na|no|pela|pelo)[ \t]+)?)([([#][ \t]*)?(?:(op[cç][aã]o|item|n[uú]mero)[ \t#:.-]*)?(?:([12])(\uFE0F?\u20E3|[ªº°])?(?![0-9]|[.,*][0-9])|(um|uma|dois|duas|primeir[oa]|segund[oa])(?![A-Za-zÀ-ÿ0-9]))(?:[ \t]+(op[cç][aã]o|item|escolha)(?![A-Za-zÀ-ÿ0-9]))?(?:([ \t]*[)\].:\-!?]+[ \t]*|[ \t,]+)([\s\S]*))?$/i;

function matchLeadingMenuOption(strippedMd: string): {
  optDigit: '1' | '2';
  remainder: string;
} | null {
  const cleanedMenuInput = strippedMd.replace(MENU_CONVERSATIONAL_PREFIX_RE, '').trim();
  if (!cleanedMenuInput) return null;
  const leadingOptMatch = cleanedMenuInput.match(LEADING_MENU_OPT_RE);
  if (!leadingOptMatch) return null;

  const hasDefiniteArticle = Boolean(leadingOptMatch[1] || leadingOptMatch[2]);
  const openSym = leadingOptMatch[3] ?? '';
  const menuWord = leadingOptMatch[4] ?? '';
  const rawDigit = leadingOptMatch[5];
  const keycapSym = leadingOptMatch[6] ?? '';
  const rawWord = (leadingOptMatch[7] ?? '').toLowerCase();
  const trailingMenuWord = leadingOptMatch[8] ?? '';
  const sep = leadingOptMatch[9] ?? '';
  const remainder = (leadingOptMatch[10] ?? '').trim();
  const hasMenuNoun = Boolean(menuWord || trailingMenuWord);

  const optDigit: '1' | '2' = rawDigit
    ? (rawDigit as '1' | '2')
    : rawWord === 'um' || rawWord === 'uma' || rawWord.startsWith('primeir')
      ? '1'
      : '2';

  // "Quero um novo valor" / "Quero um de 80": "um"/"uma" sem "opção"/"item" seguido de substantivo/preposição é artigo indefinido!
  if (
    (rawWord === 'um' || rawWord === 'uma') &&
    !hasMenuNoun &&
    remainder.length > 0 &&
    !/^(?:por[ \t]+favor|pfv?|pf|pls|plz|obrigad[oa]|obgd?|valeu|vlw|agrade[cç]o|agora|a[ií]|amigo|amiga|mano|cara|chefe|irm[aã]o)(?![A-Za-zÀ-ÿ0-9])/i.test(
      remainder
    )
  ) {
    return null;
  }

  const startsWithNumberUnit =
    !hasMenuNoun &&
    !keycapSym &&
    remainder.length > 0 &&
    /^(?:mil|milh[aã]o|milh[oõ]es|reais|real|brl|contos?|pilas?|centavos?|pix|e|ou|mais|menos|a|at[eé]|x|vezes|itens?|unidades?|parcelas?|min|minutos?|minutinhos?|seg|segundos?|segundinhos?|horas?|horinhas?|dias?|semanas?|m[eê]s|meses)(?![A-Za-zÀ-ÿ0-9])|^%/i.test(
      remainder
    );

  const hasExplicitBullet = Boolean(
    hasMenuNoun || openSym || keycapSym || /[)\].:\-!?,]/.test(sep)
  );
  const allowedBareRemainder =
    remainder.length === 0 ||
    hasExplicitBullet ||
    (hasDefiniteArticle && /^(?:de|com|por|para|pra)(?![A-Za-zÀ-ÿ0-9])/i.test(remainder)) ||
    /^(?:r\$|(?:por[ \t]+favor|pfv?|pf|pls|plz|obrigad[oa]|obgd?|valeu|vlw|agrade[cç]o|agora|a[ií]|amigo|amiga|mano|cara|chefe|irm[aã]o|quero|preciso|mand[ae]|mandar|envi[ae]|enviar|pode|escolho|prefiro|vai|sim|ok|beleza|blz|fechado|isso|reenvi\w*|manter|mantenha|continu\w*|cancel\w*|gerar|gera|fazer|faz|nov[oa]|outr[oa]|trocar|troca|mudar|muda|substituir|alterar)(?![A-Za-zÀ-ÿ0-9]))/i.test(
      remainder
    );

  if (startsWithNumberUnit || !allowedBareRemainder) {
    return null;
  }

  return { optDigit, remainder };
}

const CONTRASTIVE_NEGATED_MENU_PREFIX_RE =
  /^(?:(?:n[aã]o[ \t]+(?:quero|preciso|vou|escolho|prefiro|[eé]|vai|seria|mand[ae]|gera|faz)|esquece|esque[cç]a|sem[ \t]+ser)[ \t]+(?:(?:a|o|na|no|de)[ \t]+)?(?:(?:op[cç][aã]o|item|n[uú]mero)[ \t#:.-]*)?|n[aã]o[ \t]+(?:(?:a|o|na|no)[ \t]+(?:(?:op[cç][aã]o|item|n[uú]mero)[ \t#:.-]*)?|(?:op[cç][aã]o|item|n[uú]mero)[ \t#:.-]*))(?:([12])(?:\uFE0F?\u20E3|[ªº°])?(?![0-9]|[.,*][0-9])|(um|uma|dois|duas|primeir[oa]|segund[oa])(?![A-Za-zÀ-ÿ0-9]))(?:[ \t]+(?:op[cç][aã]o|item|escolha)(?![A-Za-zÀ-ÿ0-9]))?(?:[ \t]*[,;:.!\-]+[ \t]*(?:(?:mas|e[ \t]+sim)[ \t]+)?|[ \t]+(?:mas|e[ \t]+sim)[ \t]+)(.+)$/i;

function stripContrastiveNegatedMenuPrefix(strippedMd: string): {
  effectiveText: string;
  rejectedDigit: '1' | '2' | null;
} {
  const m = strippedMd.match(CONTRASTIVE_NEGATED_MENU_PREFIX_RE);
  if (!m) {
    return { effectiveText: strippedMd, rejectedDigit: null };
  }
  const rawDigit = m[1];
  const rawWord = (m[2] ?? '').toLowerCase();
  const rejectedDigit: '1' | '2' = rawDigit
    ? (rawDigit as '1' | '2')
    : rawWord === 'um' || rawWord === 'uma' || rawWord.startsWith('primeir')
      ? '1'
      : '2';
  return { effectiveText: m[3].trim(), rejectedDigit };
}

/**
 * Retorna `true` se o cliente incluiu dígitos extras na resposta ao menu `1 / 2` além do próprio dígito da opção
 * (usado por `ConversationEngine` para evitar reaproveitar `pendingNewAmountBrl` em entradas ambíguas como `"2 - 50 ou 100"`).
 */
export function hasUnparsedDigitsInMenuReply(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN * 2) return false;
  const strippedMd = unwrapWhatsAppMarkdown(
    stripDecorativeEmojis(normalizeHorizontalSpaces(text))
  )
    .replace(/\s+/g, ' ')
    .trim();
  if (!strippedMd || strippedMd.length > MAX_NLU_LEN) return false;

  const { effectiveText, rejectedDigit } = stripContrastiveNegatedMenuPrefix(strippedMd);
  const opt = matchLeadingMenuOption(effectiveText);
  if (opt && rejectedDigit && opt.optDigit === rejectedDigit) {
    return true;
  }
  const bodyToInspect = opt ? opt.remainder : effectiveText;
  if (!bodyToInspect) return false;

  const normalizedBody = normalizePortugueseNumberWords(bodyToInspect);
  return (
    /\d/.test(normalizedBody) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:mil|milh[aã]o|milh[oõ]es)(?![A-Za-zÀ-ÿ0-9])/i.test(normalizedBody)
  );
}

const MENU_NEW_INTENT_UNNEGATED_RE =
  /(?<!(?<![A-Za-zÀ-ÿ0-9])n[aã]o[ \t]+(?:(?:quero|preciso|precisa|vou|pode|favor)[ \t]+)?|(?<![A-Za-zÀ-ÿ0-9])(?:nem|sem)[ \t]+)(?<![A-Za-zÀ-ÿ0-9])(?:cancel(?:ar|a|e)|(?<!de[ \t]+)nov[oa]|outr[oa]|trocar|troca|mudar|muda|substituir|alterar)(?![A-Za-zÀ-ÿ0-9])/i;

const MENU_RESEND_INTENT_UNNEGATED_RE =
  /(?<!(?<![A-Za-zÀ-ÿ0-9])n[aã]o[ \t]+(?:(?:quero|preciso|precisa|vou|pode|favor|mand[ae]|mandar|envi[ae]|enviar|pass[ae]|passar)[ \t]+){0,2}|(?<![A-Za-zÀ-ÿ0-9])nem[ \t]+)(?<![A-Za-zÀ-ÿ0-9])(?:reenvi(?:ar|a|e)|mesm[oa]|manter|mantenha|mant[eé]m|continua|continuar|de[ \t]+novo|(?:mand[ae]|mandar|envi[ae]|enviar|pass[ae]|passar)[ \t]+(?:(?:a|o|essa|esse|meu|minha)[ \t]+)?(?:(?:pix|cobran[cç]a)[ \t]+)?(?:atual|ess[ae]))(?![A-Za-zÀ-ÿ0-9])/i;

/**
 * Interpreta respostas ao menu `1 / 2` de cobrança ativa em tempo O(N), tratando `"2."`, `"quero a 2"`,
 * `"É a 2"`, `"2 🙏"`, `"Não é a 1, é a 2"`, `"Pode mandar a atual"`, `"manda de novo"` (= reenviar!), `"Não cancela, manda a atual"` (= reenviar!) e `"cancela e gera de 100"` (= novo!).
 */
export function parseActiveOrderMenuReply(text: string): ActiveMenuParseResult {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN * 2) {
    return { choice: 'none', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  const strippedMd = unwrapWhatsAppMarkdown(
    stripDecorativeEmojis(normalizeHorizontalSpaces(text))
  )
    .replace(/\s+/g, ' ')
    .trim();
  if (!strippedMd || strippedMd.length > MAX_NLU_LEN) {
    return { choice: 'none', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  const { effectiveText, rejectedDigit } = stripContrastiveNegatedMenuPrefix(strippedMd);

  // Passo 1: Opção explícita 1 ou 2 ("1", "2.", "2)", "(2)", "#2", "Quero a (2)", "opção 2", "2 - gerar 80", "Não quero a 1, quero a 2")
  const matchedOpt = matchLeadingMenuOption(effectiveText);
  if (matchedOpt && (!rejectedDigit || matchedOpt.optDigit !== rejectedDigit)) {
    const { optDigit, remainder } = matchedOpt;
    const inlineAmt = remainder ? parseBrlAmountFromText(remainder) : null;

    if (
      remainder &&
      MENU_NEW_INTENT_UNNEGATED_RE.test(remainder) &&
      !(optDigit === '1' && MENU_RESEND_INTENT_UNNEGATED_RE.test(remainder))
    ) {
      return { choice: 'new', explicitOptionDigit: '2', inlineNewAmountBrl: inlineAmt };
    }

    return {
      choice: optDigit === '1' ? 'resend' : 'new',
      explicitOptionDigit: optDigit,
      inlineNewAmountBrl: optDigit === '2' ? inlineAmt : null,
    };
  }

  // Passo 2: Intenção textual NÃO negada de cancelar/substituir/novo valor (excluindo "de novo" e "Não quero cancelar"!)
  if (MENU_NEW_INTENT_UNNEGATED_RE.test(effectiveText)) {
    return {
      choice: 'new',
      explicitOptionDigit: null,
      inlineNewAmountBrl: parseBrlAmountFromText(effectiveText),
    };
  }

  // Passo 3: Intenção textual NÃO negada de reenviar/manter cobrança existente (ex: "manda de novo", "Não cancela, manda a atual")
  if (MENU_RESEND_INTENT_UNNEGATED_RE.test(effectiveText)) {
    return { choice: 'resend', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  return {
    choice: 'none',
    explicitOptionDigit: null,
    inlineNewAmountBrl: rejectedDigit ? null : parseBrlAmountFromText(strippedMd),
  };
}

const NON_PAYMENT_OBJECT_AFTER_CONFIRM_RE =
  /(?<![A-Za-zÀ-ÿ0-9])(?:confirmou|confirmaram|aprovou|aprovaram|processou|processaram)[ \t]+(?:a[ií][ \t]+|j[aá][ \t]+)?(?:o|a|os|as|meu|minha|seu|sua|nosso|nossa|esse|essa)[ \t]+(?!(?:pix|depix|pagamento|cobran[cç]a|valor|dep[oó]sito|transfer[eê]ncia|transa[cç][aã]o|comprovante|recibo)(?![A-Za-zÀ-ÿ0-9]))[A-Za-zÀ-ÿ]{3,}/i;

export function isStatusQueryMessage(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN * 2) return false;
  const n = normalizeCommandText(text);
  if (
    n &&
    /^(?:status|comprovante|meu pix|ver status|consultar|situa[cç][aã]o)(?: d[oa] (?:meu )?(?:pix|pagamento|pedido|cobran[cç]a))?$/.test(
      n
    )
  ) {
    return true;
  }

  const rawTrimmed = unwrapWhatsAppMarkdown(
    stripDecorativeEmojis(normalizeHorizontalSpaces(text))
  ).trim();
  if (!rawTrimmed || rawTrimmed.length > MAX_NLU_LEN) return false;
  const t = normalizePortugueseNumberWords(rawTrimmed);

  if (hasExplicitOrReplacementNewOrder(t)) {
    return false;
  }

  if (
    ACCOUNT_DEBITED_REPORT_RE.test(t) ||
    UNAMBIGUOUS_FINANCIAL_FAILURE_OR_REFUND_RE.test(t) ||
    (PAYMENT_FAILURE_OR_REFUND_RE.test(t) && HAS_PAYMENT_OR_BANK_CONTEXT_RE.test(t))
  ) {
    return true;
  }

  const isQuestion = t.endsWith('?');
  const hasNonPaymentArrivalSubject =
    /(?<![A-Za-zÀ-ÿ0-9])(?:sal[aá]rio|dinheiro|encomenda|entrega|mercadoria|produto|pacote|pedido)[ \t]+(?:j[aá][ \t]+|hoje[ \t]+)?(?:caiu|entrou|chegou|bateu)(?![A-Za-zÀ-ÿ0-9])|(?<![A-Za-zÀ-ÿ0-9])(?:entrou|caiu|chegou|bateu)[ \t]+(?:a[ií][ \t]+|aqui[ \t]+)?(?:um[ \t]+|uma[ \t]+|o[ \t]+|a[ \t]+|meu[ \t]+|minha[ \t]+|seu[ \t]+|sua[ \t]+)?(?:dinheiro|sal[aá]rio|encomenda|entrega|mercadoria|produto|pacote|pedido|motoboy)(?![A-Za-zÀ-ÿ0-9])|(?<![A-Za-zÀ-ÿ0-9])(?:voc[eê]s?|vcs?|tu|ele|ela|eles|elas|a[ \t]+gente|n[oó]s|algu[eé]m|todo[ \t]+mundo|pessoal|galera|motoboy|entregador)(?:[ \t]+j[aá])?[ \t]+(?:chegou|chegaram|entrou|entraram)(?![A-Za-zÀ-ÿ0-9])|(?<![A-Za-zÀ-ÿ0-9])(?:chegou|chegaram|entrou|entraram)[ \t]+(?:em[ \t]+casa|no[ \t]+trabalho|na[ \t]+loja|de[ \t]+viagem|na[ \t]+viagem|bem)(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    );
  const hasNonPaymentConfirmObject = NON_PAYMENT_OBJECT_AFTER_CONFIRM_RE.test(t);

  return (
    /(?<![A-Za-zÀ-ÿ0-9])(?:qual[ \t]+(?:[eé][ \t]+)?(?:o[ \t]+)?status|status[ \t]+d[oa][ \t]+(?:meu[ \t]+)?(?:pix|pagamento|cobran[cç]a|pedido))(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:comprovante|recibo)(?![A-Za-zÀ-ÿ0-9])/i.test(t) ||
    (!hasNonPaymentConfirmObject &&
      /(?<![A-Za-zÀ-ÿ0-9])(?:j[aá][ \t]+)?(?:confirmou|compensou|creditou|processou|receberam)(?![A-Za-zÀ-ÿ0-9])/i.test(
        t
      )) ||
    (!hasNonPaymentArrivalSubject &&
      !hasNonPaymentConfirmObject &&
      ((isQuestion &&
        /(?<![A-Za-zÀ-ÿ0-9])(?:j[aá][ \t]+)?(?:caiu|entrou|recebeu|aprovou|chegou|bateu)(?![A-Za-zÀ-ÿ0-9])/i.test(
          t
        )) ||
        /(?<![A-Za-zÀ-ÿ0-9])j[aá][ \t]+(?:caiu|entrou|recebeu|aprovou|chegou|bateu)(?![A-Za-zÀ-ÿ0-9])/i.test(
          t
        ) ||
        /(?<![A-Za-zÀ-ÿ0-9])(?:v[eê]|veja|olha|olhe|confere|confira|checa|cheque|verifica|verifique|consulta|consulte|confirma|confirme|(?:me[ \t]+)?(?:diz|diga|fala|fale|avisa|avise)|d[aá][ \t]+uma[ \t]+olhada)(?:[ \t]+(?:a[ií]|aqui|l[aá]|pra[ \t]+mim|por[ \t]+favor|pfv?|pf)){0,2}[ \t]+se(?![A-Za-zÀ-ÿ0-9])[^\n]{1,80}?(?<![A-Za-zÀ-ÿ0-9])(?:caiu|ca[ií]ram|entrou|entraram|chegou|chegaram|bateu|bateram|recebeu|receberam|aprovou|aprovaram|confirmou|confirmaram|compensou|compensaram|processou|creditou|passou|(?:foi|est[aá]|t[aá])[ \t]+pag[oa]s?|deu[ \t]+certo)(?![A-Za-zÀ-ÿ0-9])/i.test(
          t
        ) ||
        /(?<![A-Za-zÀ-ÿ0-9])(?:pix|pagamento|cobran[cç]a|valor|dep[oó]sito|transfer[eê]ncia)(?:[ \t]+pix)?(?:[ \t]+(?:d[eo]s?|da)[ \t]+(?:r\$[ \t]*)?\d[\d.,]*(?:[ \t]*(?:reais|real|contos?|pilas?))?)?(?:[ \t]+que[ \t]+(?:eu[ \t]+)?(?:fiz|mandei|enviei|paguei|passei|transferi))?[ \t]+(?:j[aá][ \t]+)?(?:caiu|ca[ií]ram|entrou|entraram|chegou|chegaram|bateu|bateram|aprovou|aprovaram|compensou|confirmou)(?![A-Za-zÀ-ÿ0-9])/i.test(
          t
        ) ||
        /(?<![A-Za-zÀ-ÿ0-9])(?:recebeu|aprovou|caiu|entrou|chegou)(?:[ \t]+(?:a[ií]|aqui))?[ \t]+(?:(?:os?|as?|meu|minha|esse|essa)[ \t]+)?(?:(?:r\$[ \t]*\d[\d.,]*|\d[\d.,]*(?:[ \t]*(?:reais|real|contos?|pilas?))?)[ \t]+(?:d[eo][ \t]+|no[ \t]+|via[ \t]+)?)?(?:pix|pagamento|cobran[cç]a|valor|comprovante|transfer[eê]ncia|dep[oó]sito)(?![A-Za-zÀ-ÿ0-9])/i.test(
          t
        ))) ||
    /(?<![A-Za-zÀ-ÿ0-9])deu[ \t]+(?:tudo[ \t]+)?certo(?:[ \t?!.,]*$|[ \t]+(?:a[ií]|aqui|l[aá]|ent[aã]o|agora|mesmo)(?![A-Za-zÀ-ÿ0-9])|[ \t]+(?:(?:com|no|na)[ \t]+)?(?:o[ \t]+|a[ \t]+|meu[ \t]+|minha[ \t]+|esse[ \t]+|essa[ \t]+)?(?:pix|pagamento|cobran[cç]a|transfer[eê]ncia|dep[oó]sito|transa[cç][aã]o|valor|link|qr)(?![A-Za-zÀ-ÿ0-9]))/i.test(
      t
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:foi|est[aá]|t[aá])[ \t]+(?:confirmad[oa]|aprovad[oa]|compensad[oa]|recebid[oa]|processad[oa]|creditad[oa]|identificad[oa])(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    )
  );
}

const POST_PAYMENT_VERB_MODIFIER_TOKEN =
  '(?:o|a|os|as|um|uma|meu|minha|seu|sua|esse|essa|aquele|aquela|agora|mesmo|hoje|j[aá]|aqui|a[ií]|l[aá]|ali|rapidinho|r[aá]pido|direitinho|certinho|ontem|cedo|tamb[eé]m|logo|(?:pra|para|a)[ \\t]+(?:voc[eê]|vc|vcs|tu|ti|a[ií]|l[aá]|sua[ \\t]+conta|conta|chave|loja|empresa)|(?:pelo|pela|no|na|via|do|da)[ \\t]+(?:app|aplicativo|banco|celular|caixa|nubank|inter|ita[uú]|bradesco|santander|bb|sicredi|sicoob|picpay|mercadopago|c6|neon|next|pagbank|pagseguro|xp|btg|ame|recargapay)|de[ \\t]+novo|outra[ \\t]+vez)';

const POST_PAYMENT_ACTIVE_CLAUSE_RE = new RegExp(
  `(?<![A-Za-zÀ-ÿ0-9])(?:j[aá][ \\t]+)?${OPT_CLITIC_PRONOUN}(?:fiz|efetuei|realizei|mandei|enviei|transferi|passei|conclu[ií]|finalizei|completei)(?:[ \\t]+${POST_PAYMENT_VERB_MODIFIER_TOKEN}){0,5}[ \\t]+(?:(?:(?:pix|pagamento|dep[oó]sito|cobran[cç]a|valor|comprovante|recibo)|transfer[eê]ncia(?![ \\t]+(?:d[eo]s?|da)[ \\t]+(?:arquivos?|dados|fotos?|v[ií]deos?|contatos?|conversas?|chamadas?|alunos?|escola|faculdade|curso|cargo|setor|ve[ií]culos?|carros?|motos?|pontos?|milhas?)(?![A-Za-zÀ-ÿ0-9])))(?![A-Za-zÀ-ÿ0-9])|r\\$[ \\t]*\\d|\\d[\\d.,]*(?![\\d.,]|[ \\t]*(?:${PHYSICAL_OR_SPEC_SUFFIX_UNIT_PATTERN}|min|mins|minutos?|minutinhos?|seg|segs|segundos?|segundinhos?|instantes?|instantinhos?|horas?|horinhas?|h|hs|dias?|semanas?|m[eê]s|meses|anos?)(?![A-Za-zÀ-ÿ0-9])))`,
  'i'
);

const UNRELATED_EXPENSE_CONTEXT_RE =
  /(?<![A-Za-zÀ-ÿ0-9])(?:(?:no|na|do|da|pro|pra|pelo|pela)[ \t]+(?:mercado|supermercado|padaria|farm[aá]cia|posto|restaurante|bar|lanche|almo[cç]o|jantar|uber|t[aá]xi|estacionamento|ped[aá]gio|shopping|feira|a[cç]ougue|escola|faculdade|hospital|oficina)|(?:o|a|meu|minha)[ \t]+(?:aluguel|condom[ií]nio|[aá]gua|luz|energia|g[aá]s|iptu|ipva|mercado|jantar|almo[cç]o))(?![A-Za-zÀ-ÿ0-9])/i;

/**
 * Detecta mensagens/legendas pós-pagamento sem bloquear pedidos em 1ª pessoa ("Pago R$ 50", "Por R$ 50 pago agora")
 * nem negações ("Não paguei o pix de 50 ainda", "Paguei não") nem novos pedidos ("Fiz uma compra de 50, pode mandar o pix?").
 */
export function isPaymentConfirmationMessage(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN * 2) return false;
  const rawTrimmed = unwrapWhatsAppMarkdown(
    stripDecorativeEmojis(normalizeHorizontalSpaces(text))
  ).trim();
  if (!rawTrimmed || rawTrimmed.length > MAX_NLU_LEN) return false;

  const t = normalizePortugueseNumberWords(rawTrimmed);

  if (
    hasExplicitOrReplacementNewOrder(t) ||
    (UNRELATED_EXPENSE_CONTEXT_RE.test(t) &&
      !/(?<![A-Za-zÀ-ÿ0-9])(?:pix|depix|cobran[cç]a|comprovante|recibo)(?![A-Za-zÀ-ÿ0-9])/i.test(
        t
      )) ||
    /(?<![A-Za-zÀ-ÿ0-9])quase[ \t]+(?:que[ \t]+)?(?:eu[ \t]+)?(?:(?:te|lhe|lhes|me|nos)[ \t]+)?(?:fiz|paguei|quitei|depositei|mandei|enviei|passei|transferi|conclu[ií]|finalizei|completei)(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    ) ||
    (PAYMENT_FAILURE_OR_REFUND_RE.test(t) && !ACCOUNT_DEBITED_REPORT_RE.test(t)) ||
    /(?:^|[ \t,;:.!?]|(?<![A-Za-zÀ-ÿ0-9])(?:eu|j[aá])[ \t]+)(?:ainda[ \t]+)?n[aã]o[ \t]+(?:j[aá][ \t]+)?(?:(?:te|lhe|lhes|me|nos)[ \t]+)?(?:paguei|quitei|depositei|passei|fiz|efetuei|realizei|mandei|enviei|transferi|conclu[ií]|finalizei|completei|foi|foram|est[aá]|est[aã]o|t[aá]|t[aã]o|consegui|descontou|descontaram|debitou|debitaram|saiu|sa[ií]ram|concluiu|completou|finalizou|processou|confirmou|aprovou|autorizou|compensou|creditou|caiu|ca[ií]ram|cairam|entrou|entraram)(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:paguei|quitei|depositei|passei|fiz|efetuei|realizei|mandei|enviei|transferi|conclu[ií]|finalizei|completei|pag[oa]s?)[ \t]+n[aã]o(?![A-Za-zÀ-ÿ0-9])/i.test(
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
    /(?<![A-Za-zÀ-ÿ0-9])(?:eu|se|caso|amanh[aã])[ \t]+/i.test(t) ||
    /(?<![A-Za-zÀ-ÿ0-9])por[ \t]+(?:r\$[ \t]*)?\d/i.test(t);
  const tWithoutDatesAndHours = stripDatesAndHours(t);

  if (
    !isQuestion &&
    !hasConditionalOfferPrefix &&
    (/^[ \t]*pag[oa]s?(?:[ \t]+(?:o|a|os|as|meu|minha)[ \t]+(?:pix|pagamento|cobran[cç]a|valor)(?![A-Za-zÀ-ÿ0-9])|[!,.:;-]+[ \t]*(?:o[ \t]+|meu[ \t]+|pix(?![A-Za-zÀ-ÿ0-9])|pagamento(?![A-Za-zÀ-ÿ0-9])|r\$\s*\d|\d))/i.test(
      t
    ) ||
      /^[ \t]*(?:feit[oa]s?|realizad[oa]s?|efetuad[oa]s?|enviad[oa]s?|transferid[oa]s?|depositad[oa]s?|quitad[oa]s?|conclu[ií]d[oa]s?|finalizad[oa]s?|completad[oa]s?)(?:[!,.:;-]+[ \t]*|[ \t]+)(?:(?:o|a|os|as|meu|minha)[ \t]+)?(?:pix|pagamento|cobran[cç]a|valor|r\$[ \t]*\d|\d)/i.test(
        t
      ) ||
      /(?:(?<![A-Za-zÀ-ÿ0-9])r\$[ \t]*\d[\d.,]*|(?<![-\wÀ-ÿºª°.,])\d[\d.,]*)[ \t]*(?:(?:reais|real|contos?|pilas?)[ \t]+)?(?:j[aá][ \t]+)?(?:(?:foi|foram|est[aá]|est[aã]o|t[aá]|t[aã]o)[ \t]+)?(?:pago(?![ \t]+(?:agora|hoje|amanh[aã](?![A-Za-zÀ-ÿ0-9])|depois|se(?![A-Za-zÀ-ÿ0-9])|(?:os?[ \t]+)?(?:r\$[ \t]*)?\d))|paga|pagos|pagas|enviad[oa]s?|transferid[oa]s?|feit[oa]s?|realizad[oa]s?|efetuad[oa]s?|depositad[oa]s?|quitad[oa]s?|conclu[ií]d[oa]s?|finalizad[oa]s?|completad[oa]s?)(?![A-Za-zÀ-ÿ0-9])/i.test(
        tWithoutDatesAndHours
      ))
  ) {
    return true;
  }

  return (
    /(?<![A-Za-zÀ-ÿ0-9])(?:paguei|quitei|depositei)(?![A-Za-zÀ-ÿ0-9])/i.test(t) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:comprovante|recibo)(?![A-Za-zÀ-ÿ0-9])/i.test(t) ||
    ACCOUNT_DEBITED_REPORT_RE.test(t) ||
    /(?<![A-Za-zÀ-ÿ0-9])segue(?:[ \t]+(?:a[ií]|aqui|anexo|abaixo))?[ \t]+(?:(?:o|a|os|meu|minha)[ \t]+)?(?:pix|pagamento|comprovante|recibo|transfer[eê]ncia|dep[oó]sito)(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:t[aá]|est[aá]|foi|foram|est[aã]o|t[aã]o)[ \t]+(?:pag[oa]s?|enviad[oa]s?|transferid[oa]s?|feit[oa]s?|realizad[oa]s?|efetuad[oa]s?|depositad[oa]s?|quitad[oa]s?|conclu[ií]d[oa]s?|finalizad[oa]s?|completad[oa]s?)(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    ) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:pix|pagamento|cobran[cç]a|transfer[eê]ncia|transa[cç][aã]o|dep[oó]sito|valor)(?:[ \t]+pix)?(?:[ \t]+d[eo][ \t]+(?:r\$[ \t]*)?[\d.,]+(?:[ \t]+(?:reais|real|contos?|pilas?))?)?[ \t]+(?:j[aá][ \t]+)?(?:(?:foi|foram|est[aá]|est[aã]o|t[aá]|t[aã]o)[ \t]+)?(?:pag[oa]s?|enviad[oa]s?|feit[oa]s?|realizad[oa]s?|efetuad[oa]s?|conclu[ií]d[oa]s?|finalizad[oa]s?|completad[oa]s?|transferid[oa]s?|depositad[oa]s?|quitad[oa]s?)(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    ) ||
    (!isQuestion && POST_PAYMENT_ACTIVE_CLAUSE_RE.test(t)) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:acabei[ \t]+de|terminei[ \t]+de|consegui)[ \t]+(?:(?:te|lhe|lhes)[ \t]+)?(?:(?:pagar|fazer|enviar|mandar|transferir|depositar|passar|quitar)(?![A-Za-zÀ-ÿ0-9])|(?:concluir|finalizar|completar|efetuar|realizar)[ \t]+(?:(?:o|a|os|as|meu|minha|esse|essa)[ \t]+)?(?:pix|pagamento|dep[oó]sito|transfer[eê]ncia|cobran[cç]a|transa[cç][aã]o)(?![A-Za-zÀ-ÿ0-9]))/i.test(
      t
    )
  );
}

/**
 * Filtro estrito para o modo `keyword_only` quando a sessão já está encerrada (`IDLE`, sem cobrança pendente):
 * só permite despertar o robô sem palavra-chave ("pix"/"pagar") se a mensagem tiver semântica inequívoca de
 * consulta/confirmação financeira pós-pedido — jamais atravessa conversas pessoais do lojista!
 */
const FOLLOWUP_INTERJECTION_PREFIX_RE =
  /^(?:(?:pronto|prontinho|feito|certinho|certo|beleza|blz|ok|okay|show|top|perfeito|maravilha|oi|ol[aá]|opa|e[ \t]+a[ií]|bom[ \t]+dia|boa[ \t]+tarde|boa[ \t]+noite|amigo|amiga|chefe|mano|irm[aã]o)(?![A-Za-zÀ-ÿ0-9])[ \t,;.!\-]*)+/i;

export function isPostOrderFollowUpMessage(text: string): boolean {
  if (!isStatusQueryMessage(text) && !isPaymentConfirmationMessage(text)) {
    return false;
  }

  const rawTrimmed = unwrapWhatsAppMarkdown(
    stripDecorativeEmojis(normalizeHorizontalSpaces(text))
  ).trim();
  if (!rawTrimmed || rawTrimmed.length > MAX_NLU_LEN) return false;
  const t = normalizePortugueseNumberWords(rawTrimmed);

  // Nunca desperta o robô em conversas sobre celular/cartão/lojas de terceiros/despesas cotidianas/arquivos/reuniões/entregas!
  if (
    UNRELATED_EXPENSE_CONTEXT_RE.test(t) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:celular|chip|cart[aã]o|cr[eé]dito|fatura|boleto|ingresso|passagem|voo|hotel|amazon|shopee|mercado[ \t]*livre|ifood|uber|shein|aliexpress|arquivos?|dados|fotos?|v[ií]deos?|reuni[aã]o|or[cç]amento|consulta|exame|encomenda|entrega|mercadoria|ve[ií]culos?|carros?|motos?|escola|faculdade|curso)(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    )
  ) {
    return false;
  }

  const strippedPrefixRaw = rawTrimmed.replace(FOLLOWUP_INTERJECTION_PREFIX_RE, '').trim();
  const tCore = normalizePortugueseNumberWords(strippedPrefixRaw || rawTrimmed);
  const cmd = normalizeCommandText(strippedPrefixRaw || text);
  if (
    cmd &&
    /^(?:status|ver status|qual (?:[eé] )?(?:o )?status|consultar|consultar status|situa[cç][aã]o|recibo|pago|paga|pagos|(?:j[aá] )?(?:t[aá]|est[aá]|foi) pago(?: (?:j[aá]|a[ií]|aqui|agora|sim))?|(?:j[aá] )?(?:te )?(?:paguei|quitei|depositei|transferi|enviei|mandei|fiz|passei|conclu[ií]|finalizei|completei)(?: (?:j[aá]|a[ií]|aqui|agora|l[aá]|hoje))?|(?:acabei|terminei) de (?:te )?(?:pagar|transferir|depositar|enviar|mandar|fazer|quitar)(?: (?:j[aá]|a[ií]|aqui|agora))?|(?:j[aá] )?(?:caiu|entrou|bateu|compensou|confirmou|aprovou|recebeu)(?: (?:j[aá]|a[ií]|aqui|na conta))?|estornou|foi estornado|reembolsou|foi reembolsado)$/.test(
      cmd
    )
  ) {
    return true;
  }

  return (
    ACCOUNT_DEBITED_REPORT_RE.test(t) ||
    UNAMBIGUOUS_FINANCIAL_FAILURE_OR_REFUND_RE.test(t) ||
    /(?<![A-Za-zÀ-ÿ0-9])(?:cobran[cç]a|recibo|dep[oó]sito|transa[cç][aã]o|qr[ \t]*code|transfer[eê]ncia(?![ \t]+(?:d[eo]s?|da)[ \t]+(?:arquivos?|dados|fotos?|v[ií]deos?)))(?![A-Za-zÀ-ÿ0-9])/i.test(
      t
    ) ||
    /^(?:j[aá][ \t]+)?(?:(?:acabei|terminei)[ \t]+de[ \t]+)?(?:(?:te|lhe|lhes)[ \t]+)?(?:(?:paguei|pagar|quitei|quitar|depositei|depositar|transferi|transferir)(?:[ \t]+(?:j[aá]|agora|a[ií]|aqui|l[aá]|hoje|pra[ \t]+voc[eê]|pra[ \t]+vc|os?|as?|esse|essa|o[ \t]+valor)){0,3}(?:[ \t]+(?:r\$[ \t]*\d[\d.,]*|\d[\d.,]*(?:[ \t]*(?:reais|real|contos?|pilas?))?))?|(?:enviei|enviar|mandei|mandar|passei|passar|fiz|fazer|conclu[ií]|finalizei|completei)(?:[ \t]+(?:j[aá]|agora|a[ií]|aqui|l[aá]|hoje|pra[ \t]+voc[eê]|pra[ \t]+vc|o[ \t]+valor)){0,2}[ \t]+(?:(?:os?|as?|esse|essa)[ \t]+(?:\d[\d.,]*(?:[ \t]*(?:reais|real|contos?|pilas?))?|r\$[ \t]*\d[\d.,]*)|r\$[ \t]*\d[\d.,]*|\d[\d.,]*[ \t]+(?:reais|real|contos?|pilas?)))(?:[ \t]+(?:j[aá]|agora|a[ií]|aqui|l[aá]|hoje|pra[ \t]+voc[eê]|pra[ \t]+vc)){0,2}[ \t.!]*$/i.test(
      tCore
    ) ||
    /^(?:(?:j[aá][ \t]+)?(?:t[aá]|est[aá]|foi|foram|est[aã]o|t[aã]o)[ \t]+pag[oa]s?(?:[ \t]+j[aá])?[ \t]+(?:(?:os?|as?|esse|essa|o[ \t]+valor[ \t]+de)[ \t]+)?(?:r\$[ \t]*\d[\d.,]*|\d[\d.,]*(?:[ \t]*(?:reais|real|contos?|pilas?))?)|(?:(?:os?|as?)[ \t]+)?(?:r\$[ \t]*\d[\d.,]*|\d[\d.,]*(?:[ \t]*(?:reais|real|contos?|pilas?))?)[ \t]+(?:j[aá][ \t]+)?(?:(?:t[aá]|est[aá]|foi|foram|est[aã]o|t[aã]o)[ \t]+)?pag[oa]s?)(?:[ \t]+(?:j[aá]|agora|a[ií]|aqui|l[aá]|hoje)){0,2}[ \t.!]*$/i.test(
      tCore
    ) ||
    /^(?:(?:v[eê]|veja|olha|olhe|confere|confira)[ \t]+(?:a[ií][ \t]+)?se[ \t]+)?(?:j[aá][ \t]+)?(?:caiu|ca[ií]ram|entrou|entraram|bateu|bateram|compensou|compensaram|confirmou|confirmaram|aprovou|aprovaram|recebeu|receberam)(?:[ \t]+(?:a[ií]|aqui|na[ \t]+conta|no[ \t]+banco|l[aá]|agora)){0,2}[ \t]+(?:(?:os?|as?|esse|essa|o[ \t]+valor[ \t]+d[eo])[ \t]+)?(?:r\$[ \t]*\d[\d.,]*|\d[\d.,]*(?:[ \t]*(?:reais|real|contos?|pilas?))?)(?:[ \t]+(?:a[ií]|aqui|na[ \t]+conta|no[ \t]+banco|l[aá]|agora)){0,2}[ \t.!?]*$/i.test(
      tCore
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
