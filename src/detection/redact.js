export function redact(message, findings) {
  const sorted = [...findings].sort((a, b) => b.start - a.start);
  let result = message;
  for (const f of sorted) {
    result =
      result.slice(0, f.start) +
      `[REDACTED_${f.category.toUpperCase()}]` +
      result.slice(f.end);
  }
  return result;
}
