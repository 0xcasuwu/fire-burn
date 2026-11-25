// lib/throttle.js — keep `metashrew_view` under the RPC's limit (20 requests/minute on the keyless /v4/jsonrpc
// path, measured 2026-11-25: "Rate limit exceeded (20 req/min)"). Sliding 60 s window; a server-side
// rate-limit answer waits out one window and retries once, then surfaces. Time and sleep are injectable for tests.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

export function throttleRpc(rpc, { method = 'metashrew_view', perMinute = 18, now = () => Date.now(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)), onWait } = {}) {
  const stamps = [];
  let chain = Promise.resolve();
  const run = async (m, params) => {
    for (let attempt = 0; ; attempt++) {
      for (;;) {
        const t = now();
        while (stamps.length && t - stamps[0] >= 60_000) stamps.shift();
        if (stamps.length < perMinute) break;
        const wait = 60_000 - (t - stamps[0]) + 50;
        if (onWait) onWait(wait);
        await sleep(wait);
      }
      stamps.push(now());
      try {
        return await rpc(m, params);
      } catch (e) {
        if (attempt === 0 && /rate limit/i.test(String(e && e.message))) {
          if (onWait) onWait(61_000);
          await sleep(61_000);
          continue;
        }
        throw e;
      }
    }
  };
  return (m, params) => {
    if (m !== method) return rpc(m, params);
    const p = chain.then(() => run(m, params));
    chain = p.catch(() => {});
    return p;
  };
}
