/**
 * Utilitários de validação matemática de CPF/CNPJ e extração de valores em Reais (BRL).
 * Essencial para evitar rejeição bancária nos gateways Pix-to-Crypto com trava de titularidade.
 */

export function onlyDigits(value: string): string {
  return value.replace(/\D/g, '');
}

/**
 * Valida matematicamente os dígitos verificadores de um CPF brasileiro (11 dígitos).
 */
export function isValidCpf(rawCpf: string): boolean {
  const cpf = onlyDigits(rawCpf);
  if (cpf.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(cpf)) return false; // Rejeita sequências repetidas como 111.111.111-11

  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += Number(cpf[i]) * (10 - i);
  }
  let remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  if (remainder !== Number(cpf[9])) return false;

  sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += Number(cpf[i]) * (11 - i);
  }
  remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  return remainder === Number(cpf[10]);
}

/**
 * Valida matematicamente os dígitos verificadores de um CNPJ brasileiro (14 dígitos).
 */
export function isValidCnpj(rawCnpj: string): boolean {
  const cnpj = onlyDigits(rawCnpj);
  if (cnpj.length !== 14) return false;
  if (/^(\d)\1{13}$/.test(cnpj)) return false;

  const calcDigit = (base: string, weights: number[]): number => {
    let sum = 0;
    for (let i = 0; i < weights.length; i++) {
      sum += Number(base[i]) * weights[i];
    }
    const mod = sum % 11;
    return mod < 2 ? 0 : 11 - mod;
  };

  const weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  const weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

  const d1 = calcDigit(cnpj.slice(0, 12), weights1);
  if (d1 !== Number(cnpj[12])) return false;

  const d2 = calcDigit(cnpj.slice(0, 13), weights2);
  return d2 === Number(cnpj[13]);
}

/**
 * Valida CPF ou CNPJ e retorna os dígitos limpos ou null se inválido.
 */
export function validateAndCleanDocument(input: string): { valid: boolean; digits: string; type?: 'CPF' | 'CNPJ' } {
  const digits = onlyDigits(input);
  if (digits.length === 11 && isValidCpf(digits)) {
    return { valid: true, digits, type: 'CPF' };
  }
  if (digits.length === 14 && isValidCnpj(digits)) {
    return { valid: true, digits, type: 'CNPJ' };
  }
  return { valid: false, digits };
}

export function maskDocument(digits: string): string {
  if (digits.length === 11) {
    return `${digits.slice(0, 3)}.***.***-${digits.slice(9)}`;
  }
  if (digits.length === 14) {
    return `${digits.slice(0, 2)}.***.***/****-${digits.slice(12)}`;
  }
  return digits;
}

/**
 * Extrai um valor monetário em Reais de uma mensagem de texto do WhatsApp.
 * Exemplos aceitos: "150", "R$ 150,50", "pix de 1.250,00", "25.90", "quero pagar 80 reais"
 */
export function parseBrlAmountFromText(text: string): number | null {
  const cleaned = text.trim();

  // Evita confundir um CPF (11 dígitos seguidos) com valor em Reais
  const pureDigits = onlyDigits(cleaned);
  if (pureDigits.length >= 11 && !cleaned.includes(',') && !cleaned.toLowerCase().includes('r$')) {
    return null;
  }

  // Procura padrões numéricos monetários (ex: 1.250,50 ou 150,50 ou 150.50 ou 150)
  const regex = /(?:r\$\s*)?(\d{1,3}(?:\.\d{3})+,\d{1,2}|\d+,\d{1,2}|\d+\.\d{1,2}|\d+)/i;
  const match = cleaned.match(regex);
  if (!match) return null;

  let rawNumber = match[1];
  if (rawNumber.includes(',') && rawNumber.includes('.')) {
    // Formato brasileiro com milhar: 1.250,50 -> 1250.50
    rawNumber = rawNumber.replace(/\./g, '').replace(',', '.');
  } else if (rawNumber.includes(',')) {
    // Formato decimal brasileiro: 150,50 -> 150.50
    rawNumber = rawNumber.replace(',', '.');
  }

  const amount = Number(rawNumber);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 500_000) {
    return null;
  }
  return Math.round(amount * 100) / 100;
}

export function formatBrl(amount: number): string {
  return amount.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}
