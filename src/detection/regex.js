import { severityFor } from "./severity.js";

export function luhnValid(digits) {
  if (digits.length < 13) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (Number.isNaN(n)) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

const IBAN_LENGTHS = {
  DE: 22, GB: 22, FR: 27, ES: 24, IT: 27, NL: 18, BE: 16,
  AT: 20, CH: 21, IE: 22, PT: 25, DK: 18, NO: 15, SE: 24,
  FI: 18, PL: 28, CZ: 24, SK: 24, GR: 27, LU: 20,
};

export function ibanValid(value) {
  const stripped = value.replace(/\s+/g, "").toUpperCase();
  const country = stripped.slice(0, 2);
  if (!IBAN_LENGTHS[country]) return false;
  if (stripped.length !== IBAN_LENGTHS[country]) return false;

  const rearranged = stripped.slice(4) + stripped.slice(0, 4);
  let numeric = "";
  for (const ch of rearranged) {
    if (ch >= "A" && ch <= "Z") {
      numeric += (ch.charCodeAt(0) - 55).toString();
    } else if (ch >= "0" && ch <= "9") {
      numeric += ch;
    } else {
      return false;
    }
  }

  let remainder = 0;
  for (const digit of numeric) {
    remainder = (remainder * 10 + parseInt(digit, 10)) % 97;
  }
  return remainder === 1;
}

// Order matters: more-specific patterns first so they win on overlap.
export const PATTERNS = [
  {
    name: "jwt",
    regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    category: "jwt",
  },
  {
    name: "private_key",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    category: "private_key",
  },
  {
    name: "aws_access_key",
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    category: "api_key",
  },
  {
    name: "github_pat",
    regex: /\bghp_[A-Za-z0-9]{36}\b/g,
    category: "api_key",
  },
  {
    name: "google_api_key",
    regex: /\bAIza[0-9A-Za-z_-]{31,35}\b/g,
    category: "api_key",
  },
  {
    name: "stripe_key",
    regex: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    category: "api_key",
  },
  {
    name: "slack_webhook",
    regex: /https:\/\/hooks\.slack\.com\/services\/\S+/g,
    category: "api_key",
  },
  {
    name: "bearer_token",
    regex: /\bBearer\s+[A-Za-z0-9._-]+\b/g,
    category: "api_key",
  },
  {
    name: "credit_card",
    regex: /\b(?:\d[ -]?){12,18}\d\b/g,
    category: "credit_card",
    validate: (match) => luhnValid(match.replace(/[ -]/g, "")),
  },
  {
    name: "ssn",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    category: "ssn",
  },
  {
    name: "iban",
    regex: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){10,30}\b/g,
    category: "iban",
    validate: (match) => ibanValid(match),
  },
  {
    name: "email",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    category: "email",
  },
];

function overlapsAny(start, end, findings) {
  for (const f of findings) {
    if (start < f.end && f.start < end) return true;
  }
  return false;
}

export function regexDetector(message) {
  const findings = [];
  for (const p of PATTERNS) {
    p.regex.lastIndex = 0;
    let m;
    while ((m = p.regex.exec(message)) !== null) {
      const value = m[0];
      if (p.validate && !p.validate(value)) continue;
      const start = m.index;
      const end = m.index + value.length;
      if (overlapsAny(start, end, findings)) continue;
      findings.push({
        category: p.category,
        source: "regex",
        start,
        end,
        severity: severityFor(p.category),
      });
    }
  }
  return findings;
}
