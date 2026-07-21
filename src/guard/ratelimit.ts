// In-process sliding-window counter. v0.1 assumes a single replica;
// swap for a Redis token bucket when horizontal scaling is needed (not in scope).
const windows = new Map<string, number[]>();

export function checkRate(agentId: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const arr = (windows.get(agentId) ?? []).filter((t) => now - t < windowMs);
  if (arr.length >= limit) { windows.set(agentId, arr); return false; }
  arr.push(now);
  windows.set(agentId, arr);
  return true;
}
