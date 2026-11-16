/**
 * Utilitários de extração segura de valores monetários em Reais (BRL) e formatação.
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

  const sanitized = cleaned
    // Remove telefones, CPFs/CNPJs, datas (16/11, 16/11/2026) e horários (10h, 14:30)
    .replace(/\+?\d{0,3}\s*\(\d{2}\)\s*\d{4,5}[-\s]?\d{4}/g, ' ')
    .replace(/\b\d{4,5}-\d{4}\b/g, ' ')
    .replace(/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, ' ')
    .replace(/\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g, ' ')
    .replace(/\b\d{8,}\b/g, ' ')
    .replace(/\b\d{1,2}\/\d{1,2}(?:\/\d{2,4})?\b/g, ' ')
    .replace(/\b\d{1,2}:\d{2}\b/g, ' ')
    .replace(/\b\d{1,2}h(?:\d{2})?\b/gi, ' ')
    // Evita que "quero fazer 1 pix" / "me manda 1 pix" seja confundido com R$ 1,00!
    .replace(/\b1\s+pix\b/gi, ' um pix ');

  // Camada 1: precedido por R$ (ex: "R$ 150,00.", "R$ 10.000")
  const explicitPrefix = new RegExp(`r\\$\\s*(${NUM_CORE})(?![.,]\\d|\\d)`, 'i');
  const mPrefix = sanitized.match(explicitPrefix);
  if (mPrefix) {
    return parseNumericToken(mPrefix[1]);
  }

  // Camada 2: seguido por reais / real / brl / conto
  const explicitSuffix = new RegExp(
    `(?<!\\d[.,]|\\d)(${NUM_CORE})\\s*(?:reais|real|brl|conto|contos)\\b`,
    'i'
  );
  const mSuffix = sanitized.match(explicitSuffix);
  if (mSuffix) {
    return parseNumericToken(mSuffix[1]);
  }

  // Camada 3: números candidatos na frase
  const allTokensRegex = new RegExp(`(?<!\\d[.,]|\\d)(${NUM_CORE})(?![.,]\\d|\\d)`, 'g');
  const allMatches = Array.from(sanitized.matchAll(allTokensRegex))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);

  if (allMatches.length === 0) return null;
  if (allMatches.length > 1) return null;

  return allMatches[0];
}

/**
 * Detecta mensagens pós-pagamento ("já paguei o pix de 50", "fiz o pix", "segue comprovante")
 * para não gerar uma nova cobrança duplicada por engano!
 */
export function isPaymentConfirmationMessage(text: string): boolean {
  return /\b(?:j[aá]\s+paguei|acabei\s+de\s+pagar|fiz\s+o\s+pix|mandei\s+o\s+pix|enviei\s+o\s+pix|pix\s+(?:pago|enviado|feito)|t[aá]\s+pago|segue\s+(?:o\s+)?comprovante|paguei\s+(?:o|agora))\b/i.test(
    text.trim()
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
