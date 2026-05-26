export const CATEGORY_SEVERITY = {
  credit_card: "critical",
  ssn: "critical",
  api_key: "critical",
  private_key: "critical",
  password: "critical",
  jwt: "critical",
  oauth_token: "critical",
  iban: "high",
  dob: "high",
  passport_or_national_id: "high",
  medical_record: "high",
  address: "medium",
  phone: "medium",
  email: "medium",
  name: "low",
  other: "low",
};

const RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function severityFor(category) {
  return CATEGORY_SEVERITY[category] ?? "low";
}

export function maxSeverity(findings) {
  if (findings.length === 0) return "none";
  let max = "low";
  for (const f of findings) {
    if (RANK[f.severity] > RANK[max]) max = f.severity;
  }
  return max;
}
