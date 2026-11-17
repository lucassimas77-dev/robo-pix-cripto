/**
 * Utilitários de extração segura de valores monetários em Reais (BRL),
 * coerção estrita de tipos/datas UTC, normalização de URLs e detecção de intenções em português
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

export function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) {
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

/**
 * Retorna apenas strings reais (nunca converte `false`, `true`, `0` ou objetos em texto).
 */
export function safePrimitiveString(val: unknown): string {
  return typeof val === 'string' ? val : '';
}

/**
 * Extrai identificadores/textos opcionais sem jamais aceitar booleanos (`false`/`true`), `0` ou objetos.
 */
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

/**
 * Normaliza qualquer timestamp (ISO com offset `-03:00`, UTC `Z` ou epoch numérico)
 * para formato canônico UTC `.toISOString()` (`YYYY-MM-DDTHH:mm:ss.sssZ`), garantindo
 * comparações lexicográficas exatas no SQLite e evitando `Invalid Date`.
 */
export function normalizeUtcIsoTimestamp(raw: unknown, fallbackIso?: string): string | undefined {
  if (typeof raw === 'number' && Number.isFinite(raw) && raw > 0) {
    const ms = raw < 1e11 ? raw * 1000 : raw;
    const d = new Date(ms);
    if (Number.isFinite(d.getTime())) {
      return d.toISOString();
    }
  } else if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (/^\d{10,13}$/.test(trimmed)) {
      const num = Number(trimmed);
      const ms = num < 1e11 ? num * 1000 : num;
      const d = new Date(ms);
      if (Number.isFinite(d.getTime())) {
        return d.toISOString();
      }
    } else if (trimmed) {
      const d = new Date(trimmed);
      if (Number.isFinite(d.getTime())) {
        return d.toISOString();
      }
    }
  }
  return fallbackIso;
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
  // Permite até 10.000.000 para que valores acima do teto (ex: R$ 10.000) caiam no aviso claro de limite máximo!
  if (!Number.isFinite(amount) || amount <= 0 || amount > 10_000_000) {
    return null;
  }
  return Math.round(amount * 100) / 100;
}

// Bordas numéricas seguras: aceitam pontuação de frase no final ("150.", "50, por favor") mas rejeitam "150,555" ou "1.2.3.4"
const NUM_CORE =
  '(?:\\d{1,3}(?:\\.\\d{3})+,\\d{1,2}|\\d{1,3}(?:\\.\\d{3})+(?![.,]\\d|\\d)|\\d+,\\d{1,2}(?!\\d)|\\d+\\.\\d{1,2}(?![.,]\\d|\\d)|\\d+)';

export function parseBrlAmountFromText(text: string): number | null {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) return null;
  const cleaned = text.trim();
  if (!cleaned) return null;

  // Passo 0 (O(N) sem regex backtracking): remove tokens de URL, e-mail, @handle e IDs prd_/chk_
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
    // Remove telefones completos COM ou SEM parênteses no DDD (ex: "(11) 98888-7777", "11 98888-7777", "+55 21 98888-7777")
    .replace(/(?:(?:\+\d{1,3}|\b55)[ \t]+)?(?:\(\d{2}\)|\b\d{2}\b)[ \t]*\d{4,5}[-\s]\d{4}\b/g, ' ')
    // Remove CEPs, telefones sem DDD e contas/códigos hifenizados ("01310-100", "98888-7777", "56789-0")
    .replace(/\b\d+-\d+\b/g, ' ')
    .replace(/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, ' ')
    .replace(/\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g, ' ')
    .replace(/\b\d{8,}\b/g, ' ')
    .replace(/\b\d{1,2}\/\d{1,2}(?:\/\d{2,4})?\b/g, ' ')
    .replace(/\b\d{1,2}:\d{2}\b/g, ' ')
    .replace(/\b\d{1,2}h(?:\d{2})?\b/gi, ' ');

  // Rejeita valores negativos explícitos ("-50", "pix de -50", "-50 reais", "R$ -50", "-R$ 50")
  if (
    /r\$[ \t]*-[ \t]*\d/i.test(withoutContactsAndDates) ||
    /-[ \t]*r\$[ \t]*\d/i.test(withoutContactsAndDates) ||
    /(?:^|[\s(/:=])-\d/.test(withoutContactsAndDates)
  ) {
    return null;
  }

  // Rejeita expressões de soma/multiplicação ("R$ 50 + 30", "50 + 50") para não cobrar parcela parcial
  if (/\d[ \t]*[+*][ \t]*(?:r\$[ \t]*)?\d/i.test(withoutContactsAndDates)) {
    return null;
  }

  // Rejeita porcentagens com fronteira esquerda O(N) ("Tem 10% de desconto no pix?", "200 com 10% de desconto")
  const pctRegex = new RegExp(
    `(?<!-|\\d[.,]|\\d)(?:${NUM_CORE})[ \\t]*(?:%|por[ \\t]*cento\\b|porcento\\b)`,
    'i'
  );
  if (pctRegex.test(withoutContactsAndDates)) {
    return null;
  }

  // Rejeita multiplicadores de quantidade ("quero 2 itens de R$ 50", "3 unidades de 50 reais", "2x de R$ 50")
  if (
    /\b\d+[ \t]*(?:itens?|unidades?|pe[cç]as?|produtos?|pacotes?|caixas?|kits?|ingressos?|cotas?|x|vezes|parcelas?)[ \t]+(?:de[ \t]+|por[ \t]+|a[ \t]+)?(?:r\$[ \t]*)?\d/i.test(
      withoutContactsAndDates
    )
  ) {
    return null;
  }

  const sanitized = withoutContactsAndDates
    // Remove hashtags/códigos (#80, #150) e números de pedido/referência ("pedido 150", "pedido #80", "mesa 12")
    .replace(/#[ \t]*\d+(?:[.,]\d+)?/g, ' ')
    .replace(
      /\b(?:pedido|ordem|protocolo|chamado|fatura|boleto|nota|nf|mesa|quarto|apto|apartamento|id|cod|c[oó]digo|item|op[cç][aã]o)(?:[ \t]+(?:#|n[º°o.]?[ \t]*)?|[ \t]*#[ \t]*)\d+(?:[.,]\d+)?\b/gi,
      ' '
    )
    // Remove quantidades antes da palavra "pix" ("1 pix", "quero fazer 5 pix", "me manda 2 pix"), exceto após "R$"
    .replace(/(?<!r\$[ \t]*)\b\d+[ \t]+pix\b/gi, ' pix ')
    // Remove parcelas ("3x", "2 vezes", "3 parcelas") e durações ("15 min", "2 horas", "30 dias")
    .replace(/\b\d+[ \t]*(?:x|vezes|parcelas?)\b/gi, ' ')
    .replace(/\b\d+[ \t]*(?:min|minutos?|seg|segundos?|dias?|horas?|meses|anos?)\b/gi, ' ');

  // Extrai todos os candidatos numéricos livres (sem letras/identificadores colados)
  const allTokensRegex = new RegExp(
    `(?<![-\\w@/.])(${NUM_CORE})(?![.,]\\d|\\d|[-\\w]|[ \\t]*%)`,
    'g'
  );
  const allMatches = Array.from(sanitized.matchAll(allTokensRegex))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);

  // Rejeita dúvidas/escolhas com "ou" quando há 2 ou mais números distintos na frase ("R$ 50 agora ou 100 amanhã?")
  if (
    /(?<!\d)\d+(?:[.,]\d+)?(?:[ \t]+(?:reais|real|brl|conto|contos))?[ \t]+ou[ \t]+(?:r\$[ \t]*)?\d/i.test(
      sanitized
    ) ||
    (/\bou\b/i.test(sanitized) && new Set(allMatches).size > 1)
  ) {
    return null;
  }

  // Camada 1: precedido por R$ (exige candidato único distinto)
  const explicitPrefixGlobal = new RegExp(
    `(?<!-)r\\$[ \\t]*(${NUM_CORE})(?![.,]\\d|\\d|[-\\w]|[ \\t]*%)`,
    'gi'
  );
  const prefixMatches = Array.from(sanitized.matchAll(explicitPrefixGlobal))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);
  const uniquePrefix = Array.from(new Set(prefixMatches));
  if (uniquePrefix.length > 1) return null;
  if (uniquePrefix.length === 1) return uniquePrefix[0];

  // Camada 2: seguido por reais / real / brl / conto (exige candidato único distinto)
  const explicitSuffixGlobal = new RegExp(
    `(?<![-\\w@/.])(${NUM_CORE})[ \\t]*(?:reais|real|brl|conto|contos)\\b`,
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
 * Interpreta respostas ao menu `1 / 2` de cobrança ativa em tempo O(N), sem colidir
 * com a palavra `"atual"` da Opção 2 nem confundir `"2)"`, `"*2*"`, `"opção 2"` ou `"2 - ..."` com R$ 2,00.
 */
export function parseActiveOrderMenuReply(text: string): ActiveMenuParseResult {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) {
    return { choice: 'none', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  const strippedMd = text.replace(/[*_~`]/g, '').trim();
  if (!strippedMd) {
    return { choice: 'none', explicitOptionDigit: null, inlineNewAmountBrl: null };
  }

  // Passo 1: Rótulo numérico explícito de opção 1 ou 2 no início ("1", "2", "2)", "(2)", "#2", "opção 2", "2 - gerar 80")
  const leadingOptMatch = strippedMd.match(
    /^(?:[([]\s*)?(?:#\s*)?(?:(?:op[cç][aã]o|item|n[uú]mero)[ \t#:.-]*)?([12])(?![0-9.,])(?:[)\].:,\- \t]+([\s\S]*))?$/i
  );
  if (leadingOptMatch) {
    const optDigit = leadingOptMatch[1] as '1' | '2';
    const remainder = (leadingOptMatch[2] ?? '').trim();
    const inlineAmt = remainder ? parseBrlAmountFromText(remainder) : null;

    const remLower = remainder.toLowerCase();
    const remCancelAndGen =
      remLower.includes('cancelar') &&
      remLower.includes('gerar') &&
      remLower.indexOf('cancelar') < remLower.indexOf('gerar');

    if (
      remainder &&
      (remCancelAndGen ||
        /\b(?:nov[oa]|outr[oa]|trocar|troca|mudar|muda|substituir|alterar)\b/i.test(remainder))
    ) {
      return { choice: 'new', explicitOptionDigit: '2', inlineNewAmountBrl: inlineAmt };
    }

    return {
      choice: optDigit === '1' ? 'resend' : 'new',
      explicitOptionDigit: optDigit,
      inlineNewAmountBrl: optDigit === '2' ? inlineAmt : null,
    };
  }

  // Passo 2: Intenção textual de cancelar/substituir/novo valor (avaliada ANTES de reenviar!)
  const lower = strippedMd.toLowerCase();
  const hasCancelAndGenerate =
    lower.includes('cancelar') &&
    lower.includes('gerar') &&
    lower.indexOf('cancelar') < lower.indexOf('gerar');

  if (
    hasCancelAndGenerate ||
    /\b(?:nov[oa]|outr[oa]|trocar|troca|mudar|muda|substituir|alterar)\b/i.test(strippedMd)
  ) {
    return {
      choice: 'new',
      explicitOptionDigit: null,
      inlineNewAmountBrl: parseBrlAmountFromText(strippedMd),
    };
  }

  // Passo 3: Intenção textual de reenviar/manter cobrança existente (sem negação "não")
  if (
    !/\bn[aã]o\b/i.test(strippedMd) &&
    (/\b(?:reenviar|reenvia|mesm[oa]|manter|mantenha|continua|continuar)\b/i.test(strippedMd) ||
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

  // Se o cliente pede explicitamente outro/novo Pix, não trata como mera consulta
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
 * Detecta mensagens/legendas pós-pagamento ("já paguei", "paguei 50 no pix", "fiz 50 no pix",
 * "passei 50 no pix", "depositei 50 no pix", "comprovante do pix de 50", "pix de 50 pago!")
 * em tempo O(N), sem risco de ReDoS!
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
