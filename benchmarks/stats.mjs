export function summarize(samples) {
  if (!samples.length || samples.some(n => !Number.isFinite(n) || n <= 0)) {
    throw new Error('Latency samples must be finite positive numbers');
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return {
    samples: sorted.length,
    medianMs: sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2,
    p95Ms: sorted[Math.ceil(sorted.length * 0.95) - 1],
  };
}
