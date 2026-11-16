/**
 * Utilitários de extração segura de valores monetários em Reais (BRL) e formatação.
 */

export function onlyDigits(value: string): string {
  return value.replace(/\D/g, '');
}

/**
 * Converte uma string numérica em formato brasileiro ou decimal simples para número BRL.
 * Trata corretamente:
 * - Milhar com centavos: "1.250,50" -> 1250.5
 * - Milhar inteiro com ponto: "1.000" ou "1.500" -> 1000 / 1500
 * - Decimal com vírgula: "75,50" ou "75,5" -> 75.5
 * - Decimal com ponto (1 ou 2 casas): "75.50" ou "75.5" -> 75.5
 * - Inteiro simples: "150" -> 150
 */
function parseNumericToken(token: string): number | null {
  const t = token.trim();
  if (!t) return null;

  let normalized: string;
  if (/^\d{1,3}(?:\.\d{3})+,\d{1,2}$/.test(t)) {
    // Ex: "1.250,50"
    normalized = t.replace(/\./g, '').replace(',', '.');
  } else if (/^\d{1,3}(?:\.\d{3})+$/.test(t)) {
    // Ex: "1.000", "1.500", "10.000" -> milhar brasileiro sem centavos!
    normalized = t.replace(/\./g, '');
  } else if (/^\d+,\d{1,2}$/.test(t)) {
    // Ex: "150,50"
    normalized = t.replace(',', '.');
  } else if (/^\d+\.\d{1,2}$/.test(t)) {
    // Ex: "150.50" (exatamente 1 ou 2 casas decimais)
    normalized = t;
  } else if (/^\d+$/.test(t)) {
    // Inteiro puro; ignora números de 8+ dígitos (telefones/CPFs)
    if (t.length >= 8) return null;
    normalized = t;
  } else {
    return null;
  }

  const amount = Number(normalized);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 500_000) {
    return null;
  }
  return Math.round(amount * 100) / 100;
}

const NUMBER_TOKEN_PATTERN =
  '(?:\\d{1,3}(?:\\.\\d{3})+,\\d{1,2}|\\d{1,3}(?:\\.\\d{3})+(?![\\d.,])|\\d+,\\d{1,2}(?!\\d)|\\d+\\.\\d{1,2}(?![\\d.])|\\d+)';

/**
 * Extrai com precisão um valor monetário em Reais de uma mensagem livre do WhatsApp,
 * evitando confundir telefones, horários ("10h"), quantidades ("2 itens de 50") ou opções de menu.
 */
export function parseBrlAmountFromText(text: string): number | null {
  const cleaned = text.trim();
  if (!cleaned) return null;

  // Remove telefones formatados tipo (11) 98888-7777 ou +55 11 98888-7777 e sequências longas de 8+ dígitos (tel/CPF)
  const sanitized = cleaned
    .replace(/\+?\d{0,3}\s*\(\d{2}\)\s*\d{4,5}[-\s]?\d{4}/g, ' ')
    .replace(/\b\d{4,5}-\d{4}\b/g, ' ')
    .replace(/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, ' ')
    .replace(/\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g, ' ')
    .replace(/\b\d{8,}\b/g, ' ')
    // Remove horários explícitos como "10h", "14h30", "10:30"
    .replace(/\b\d{1,2}:\d{2}\b/g, ' ')
    .replace(/\b\d{1,2}h(?:\d{2})?\b/gi, ' ');

  // Camada 1 (Alta certeza): precedido por R$ (ex: "R$ 150,00", "r$1.500")
  const explicitPrefix = new RegExp(`r\\$\\s*(${NUMBER_TOKEN_PATTERN})`, 'i');
  const mPrefix = sanitized.match(explicitPrefix);
  if (mPrefix) {
    return parseNumericToken(mPrefix[1]);
  }

  // Camada 2 (Alta certeza): seguido por reais / real / brl / conto (ex: "150 reais")
  const explicitSuffix = new RegExp(
    `(?<![\\d.,])(${NUMBER_TOKEN_PATTERN})\\s*(?:reais|real|brl|conto|contos)\\b`,
    'i'
  );
  const mSuffix = sanitized.match(explicitSuffix);
  if (mSuffix) {
    return parseNumericToken(mSuffix[1]);
  }

  // Encontra todos os números candidatos restantes na frase
  const allTokensRegex = new RegExp(`(?<![\\d.,])(${NUMBER_TOKEN_PATTERN})(?![\\d.,])`, 'g');
  const allMatches = Array.from(sanitized.matchAll(allTokensRegex))
    .map((m) => parseNumericToken(m[1]))
    .filter((v): v is number => v !== null);

  if (allMatches.length === 0) return null;

  // Se houver múltiplos números sem "R$" (ex: "quero 2 itens de 50"), é ambíguo -> retorna null para perguntar o total!
  if (allMatches.length > 1) {
    return null;
  }

  // Camada 3: único número claro na frase (ex: "pix de 150", "1.000", "50,00")
  return allMatches[0];
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
