/**
 * Utilitários de extração segura de valores monetários em Reais (BRL),
 * detecção de intenções em português e formatação.
 */

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
  const cleaned = text.trim();
  if (!cleaned) return null;

  const withoutContactsAndDates = cleaned
    // Remove telefones, CPFs/CNPJs, chaves/IDs longos, datas (16/11, 16/11/2026) e horários (10h, 14:30)
    .replace(/\+?\d{0,3}\s*\(\d{2}\)\s*\d{4,5}[-\s]?\d{4}/g, ' ')
    .replace(/\b\d{4,5}-\d{4}\b/g, ' ')
    .replace(/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, ' ')
    .replace(/\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g, ' ')
    .replace(/\b\d{8,}\b/g, ' ')
    .replace(/\b\d{1,2}\/\d{1,2}(?:\/\d{2,4})?\b/g, ' ')
    .replace(/\b\d{1,2}:\d{2}\b/g, ' ')
    .replace(/\b\d{1,2}h(?:\d{2})?\b/gi, ' ');

  // Rejeita valores negativos explícitos ("-50", "pix de -50", "-50 reais", "R$ -50", "-R$ 50")
  if (
    /r\$\s*-\s*\d/i.test(withoutContactsAndDates) ||
    /-\s*r\$\s*\d/i.test(withoutContactsAndDates) ||
    /(?:^|[\s(/:=])-\d/.test(withoutContactsAndDates)
  ) {
    return null;
  }

  // Se houver porcentagem na frase (ex: "Tem 10% de desconto no pix?" ou "200 com 10% de desconto"),
  // não assume valor unilateralmente — pede ao cliente confirmar o valor final exato em Reais.
  const pctRegex = new RegExp(`(?:${NUM_CORE})\\s*(?:%|por\\s*cento\\b|porcento\\b)`, 'i');
  if (pctRegex.test(withoutContactsAndDates)) {
    return null;
  }

  const sanitized = withoutContactsAndDates
    // Remove hashtags/códigos (#80, #150) e números de pedido/referência ("pedido 150", "pedido #80", "mesa 12")
    // Nota: preserva "pedido de 150" (onde há a preposição "de" antes do valor monetário)
    .replace(/#\s*\d+(?:[.,]\d+)?/g, ' ')
    .replace(
      /\b(?:pedido|ordem|protocolo|chamado|fatura|boleto|nota|nf|mesa|quarto|apto|apartamento|id|cod|c[oó]digo|item|op[cç][aã]o)\s*(?:#|n[º°o.]?\s*)?\d+(?:[.,]\d+)?\b/gi,
      ' '
    )
    // Remove quantidades antes da palavra "pix" ("1 pix", "quero fazer 5 pix", "me manda 2 pix"), exceto quando precedidas por "R$"
    .replace(/(?<!r\$\s*)\b\d+\s+pix\b/gi, ' pix ')
    // Remove parcelas ("3x", "2 vezes", "3 parcelas") e durações ("15 min", "2 horas", "30 dias")
    .replace(/\b\d+\s*(?:x|vezes|parcelas?)\b/gi, ' ')
    .replace(/\b\d+\s*(?:min|minutos?|seg|segundos?|dias?|horas?|meses|anos?)\b/gi, ' ');

  // Camada 1: precedido por R$ (ex: "R$ 150,00.", "R$ 10.000")
  const explicitPrefix = new RegExp(`(?<!-)r\\$\\s*(${NUM_CORE})(?![.,]\\d|\\d|\\s*%)`, 'i');
  const mPrefix = sanitized.match(explicitPrefix);
  if (mPrefix) {
    return parseNumericToken(mPrefix[1]);
  }

  // Camada 2: seguido por reais / real / brl / conto
  const explicitSuffix = new RegExp(
    `(?<!-|\\d[.,]|\\d)(${NUM_CORE})\\s*(?:reais|real|brl|conto|contos)\\b`,
    'i'
  );
  const mSuffix = sanitized.match(explicitSuffix);
  if (mSuffix) {
    return parseNumericToken(mSuffix[1]);
  }

  // Camada 3: único número candidato inequívoco na frase
  const allTokensRegex = new RegExp(`(?<!-|\\d[.,]|\\d)(${NUM_CORE})(?![.,]\\d|\\d|\\s*%)`, 'g');
  const allMatches = Array.from(sanitized.matchAll(allTokensRegex))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);

  if (allMatches.length !== 1) return null;

  return allMatches[0];
}

export function normalizeCommandText(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/^[\s!?.…,;:-]+|[\s!?.…,;:-]+$/g, '')
    .replace(/\s+/g, ' ');
}

export function isExitCommand(text: string): boolean {
  const n = normalizeCommandText(text);
  return /^(?:sair|encerrar|encerrar atendimento|finalizar atendimento|parar)$/.test(n);
}

export function isCancelCommand(text: string): boolean {
  const n = normalizeCommandText(text);
  if (
    /^(?:cancelar|cancela|reiniciar|reinicia|reset|resetar)(?:\s+(?:o\s+|a\s+|esse\s+|essa\s+|meu\s+|minha\s+)?(?:pix|cobran[cç]a|pedido|tudo|atendimento|agora))?$/.test(
      n
    )
  ) {
    return true;
  }
  return /^(?:quero|pode|favor|por favor|preciso)\s+(?:cancelar|reiniciar)(?:\s+(?:o\s+|a\s+|esse\s+|essa\s+|meu\s+|minha\s+)?(?:pix|cobran[cç]a|pedido|tudo|atendimento|agora))?$/.test(
    n
  );
}

export function isHelpCommand(text: string): boolean {
  const n = normalizeCommandText(text);
  return (
    /^(?:ajuda|help|menu|op[cç][oõ]es|instru[cç][oõ]es|comandos)$/.test(n) ||
    /\b(?:como\s+(?:funciona|fa[cç]o\s+para\s+pagar|pagar\s+no\s+pix|usar)|preciso\s+de\s+ajuda|me\s+ajuda)\b/i.test(
      n
    )
  );
}

export function isStatusQueryMessage(text: string): boolean {
  const n = normalizeCommandText(text);
  return (
    /^(?:status|comprovante|meu pix|ver status|consultar|situa[cç][aã]o)(?:\s+d[oa]\s+(?:meu\s+)?(?:pix|pagamento|pedido|cobran[cç]a))?$/.test(
      n
    ) ||
    /\b(?:qual\s+(?:[eé]\s+)?(?:o\s+)?status|status\s+d[oa]\s+(?:meu\s+)?(?:pix|pagamento|cobran[cç]a|pedido)|j[aá]\s+(?:confirmou|caiu|compensou))\b/i.test(
      n
    )
  );
}

/**
 * Detecta mensagens pós-pagamento ("já paguei o pix de 50", "paguei 50 no pix", "já fiz o pagamento de 50",
 * "pagamento de 50 feito", "tá pago", "segue comprovante") para NUNCA gerar cobrança duplicada!
 */
export function isPaymentConfirmationMessage(text: string): boolean {
  const t = text.trim();
  if (!t) return false;

  // Se o cliente pede explicitamente outro/novo Pix ("paguei ontem, quero outro pix de 80"), não é mero aviso
  if (/\b(?:quero|gera|gerar|manda|mandar|preciso|faz|fazer)\s+(?:outro|novo|mais\s+um)\b/i.test(t)) {
    return false;
  }

  return (
    /\bpaguei\b/i.test(t) ||
    /^\s*pago[!?.…\s]*$/i.test(t) ||
    /\b(?:t[aá]|est[aá])\s+pago\b/i.test(t) ||
    /\bpix\s+(?:pago|enviado|feito|realizado|efetuado|conclu[ií]do|transferido)\b/i.test(t) ||
    /\bpagamento\s+(?:de\s+[^\n]{1,35}?\s+)?(?:feito|realizado|efetuado|enviado|conclu[ií]do|pago)\b/i.test(
      t
    ) ||
    /\b(?:j[aá]\s+)?fiz\s+(?:o\s+|a\s+|um\s+)?(?:pix|pagamento|dep[oó]sito|transfer[eê]ncia)\b/i.test(
      t
    ) ||
    /\bacabei\s+de\s+(?:pagar|fazer|enviar|mandar|transferir)\b/i.test(t) ||
    /\b(?:mandei|enviei|transferi)\s+(?:o\s+|os\s+|a\s+|as\s+|um\s+)?(?:pix|pagamento|valor|comprovante|r\$\s*\d|\d)/i.test(
      t
    ) ||
    /\b(?:segue|ta\s+a[ií]|est[aá]\s+a[ií]|envio)\s+(?:o\s+)?comprovante\b/i.test(t)
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
