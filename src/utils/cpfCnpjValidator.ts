/**
 * Utilitários de extração segura de valores monetários em Reais (BRL),
 * coerção segura de primitivos, detecção de intenções em português (O(N), imune a ReDoS) e formatação.
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

export function safePrimitiveString(val: unknown): string {
  if (typeof val === 'string') return val;
  if (typeof val === 'number' && Number.isFinite(val)) return String(val);
  if (typeof val === 'boolean') return String(val);
  return '';
}

export function safeOptionalId(val: unknown): string | undefined {
  const s = safePrimitiveString(val).trim();
  return s ? s : undefined;
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

  const withoutContactsAndDates = cleaned
    // Remove telefones (sem prefixos opcionais vazios antes de \s+ — complexidade estrita O(N)!), CPFs/CNPJs, datas e horários
    .replace(/(?:\+?\d{1,3}[ \t]+)?\(\d{2}\)[ \t]?\d{4,5}[-\s]?\d{4}/g, ' ')
    .replace(/\b\d{4,5}-\d{4}\b/g, ' ')
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

  // Rejeita porcentagens ("Tem 10% de desconto no pix?", "200 com 10% de desconto")
  const pctRegex = new RegExp(`(?:${NUM_CORE})[ \\t]*(?:%|por[ \\t]*cento\\b|porcento\\b)`, 'i');
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
      /\b(?:pedido|ordem|protocolo|chamado|fatura|boleto|nota|nf|mesa|quarto|apto|apartamento|id|cod|c[oó]digo|item|op[cç][aã]o)[ \t]*(?:#|n[º°o.]?[ \t]*)?\d+(?:[.,]\d+)?\b/gi,
      ' '
    )
    // Remove quantidades antes da palavra "pix" ("1 pix", "quero fazer 5 pix", "me manda 2 pix"), exceto após "R$"
    .replace(/(?<!r\$[ \t]*)\b\d+[ \t]+pix\b/gi, ' pix ')
    // Remove parcelas ("3x", "2 vezes", "3 parcelas") e durações ("15 min", "2 horas", "30 dias")
    .replace(/\b\d+[ \t]*(?:x|vezes|parcelas?)\b/gi, ' ')
    .replace(/\b\d+[ \t]*(?:min|minutos?|seg|segundos?|dias?|horas?|meses|anos?)\b/gi, ' ');

  // Rejeita dúvidas/escolhas entre dois valores ("R$ 50 ou R$ 100?", "50 reais ou 80 reais?", "50 ou 100?")
  if (
    /\d+(?:[.,]\d+)?[ \t]*(?:reais|real|brl|conto|contos)?[ \t]+ou[ \t]+(?:r\$[ \t]*)?\d/i.test(
      sanitized
    )
  ) {
    return null;
  }

  // Camada 1: precedido por R$ (exige candidato único distinto)
  const explicitPrefixGlobal = new RegExp(
    `(?<!-)r\\$[ \\t]*(${NUM_CORE})(?![.,]\\d|\\d|[ \\t]*%)`,
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
    `(?<!-|\\d[.,]|\\d)(${NUM_CORE})[ \\t]*(?:reais|real|brl|conto|contos)\\b`,
    'gi'
  );
  const suffixMatches = Array.from(sanitized.matchAll(explicitSuffixGlobal))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);
  const uniqueSuffix = Array.from(new Set(suffixMatches));
  if (uniqueSuffix.length > 1) return null;
  if (uniqueSuffix.length === 1) return uniqueSuffix[0];

  // Camada 3: único número candidato inequívoco na frase
  const allTokensRegex = new RegExp(`(?<!-|\\d[.,]|\\d)(${NUM_CORE})(?![.,]\\d|\\d|[ \\t]*%)`, 'g');
  const allMatches = Array.from(sanitized.matchAll(allTokensRegex))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);

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

export function isStatusQueryMessage(text: string): boolean {
  const n = normalizeCommandText(text);
  if (!n) return false;
  return (
    /^(?:status|comprovante|meu pix|ver status|consultar|situa[cç][aã]o)(?: d[oa] (?:meu )?(?:pix|pagamento|pedido|cobran[cç]a))?$/.test(
      n
    ) ||
    /\b(?:qual (?:[eé] )?(?:o )?status|status d[oa] (?:meu )?(?:pix|pagamento|cobran[cç]a|pedido)|j[aá] (?:confirmou|caiu|compensou))\b/i.test(
      n
    )
  );
}

/**
 * Detecta mensagens pós-pagamento ("já paguei o pix de 50", "paguei 50 no pix", "já fiz o pagamento de 50",
 * "pagamento de 50 feito", "tá pago", "segue comprovante") em tempo O(N), sem risco de ReDoS!
 */
export function isPaymentConfirmationMessage(text: string): boolean {
  if (typeof text !== 'string' || text.length > MAX_NLU_LEN) return false;
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
    /\bpaguei\b/i.test(t) ||
    /^[ \t]*pago[!?.…\s]*$/i.test(t) ||
    /\b(?:t[aá]|est[aá])[ \t]+pago\b/i.test(t) ||
    /\bpix[ \t]+(?:pago|enviado|feito|realizado|efetuado|conclu[ií]do|transferido)\b/i.test(t) ||
    /\bpagamento[ \t]+(?:de[ \t]+(?:r\$[ \t]*)?[\d.,]+[ \t]+(?:reais[ \t]+)?)?(?:feito|realizado|efetuado|enviado|conclu[ií]do|pago)\b/i.test(
      t
    ) ||
    /\b(?:j[aá][ \t]+)?fiz[ \t]+(?:o[ \t]+|a[ \t]+|um[ \t]+)?(?:pix|pagamento|dep[oó]sito|transfer[eê]ncia)\b/i.test(
      t
    ) ||
    /\bacabei[ \t]+de[ \t]+(?:pagar|fazer|enviar|mandar|transferir)\b/i.test(t) ||
    /\b(?:mandei|enviei|transferi)[ \t]+(?:o[ \t]+|os[ \t]+|a[ \t]+|as[ \t]+|um[ \t]+)?(?:pix|pagamento|valor|comprovante|r\$[ \t]*\d|\d)/i.test(
      t
    ) ||
    /\b(?:segue|ta[ \t]+a[ií]|est[aá][ \t]+a[ií]|envio)[ \t]+(?:o[ \t]+)?comprovante\b/i.test(t)
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
