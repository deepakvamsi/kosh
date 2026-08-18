// Lightweight, dependency-free password-strength estimate. It is not a full zxcvbn
// dictionary analysis, but it steers users away from weak passwords using entropy from
// length + character variety, with a small penalty for obvious repetition. Computed
// entirely locally — no network, no new dependency — consistent with Kosh's air-seal.

export type Strength = { score: 0 | 1 | 2 | 3 | 4; label: string; entropyBits: number }

const LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'] as const

export function estimateStrength(pw: string): Strength {
  if (!pw) return { score: 0, label: LABELS[0], entropyBits: 0 }

  let pool = 0
  if (/[a-z]/.test(pw)) pool += 26
  if (/[A-Z]/.test(pw)) pool += 26
  if (/[0-9]/.test(pw)) pool += 10
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33

  const bits = Math.round(pw.length * Math.log2(pool || 1))
  const adjusted = /(.)\1{2,}/.test(pw) ? bits * 0.8 : bits // penalise runs like "aaaa"

  let score: Strength['score'] = 0
  if (adjusted >= 100) score = 4
  else if (adjusted >= 70) score = 3
  else if (adjusted >= 45) score = 2
  else if (adjusted >= 28) score = 1

  return { score, label: LABELS[score], entropyBits: bits }
}
