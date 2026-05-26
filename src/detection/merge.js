function overlaps(a, b) {
  return a.start < b.end && b.start < a.end;
}

export function merge(regexFindings, llmFindings) {
  const out = [...regexFindings];
  for (const lf of llmFindings) {
    if (!out.some((rf) => overlaps(lf, rf))) {
      out.push(lf);
    }
  }
  out.sort((a, b) => a.start - b.start);
  return out;
}
