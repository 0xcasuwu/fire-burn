// lib/config.js — the only knobs. The RPC origin here MUST match the CSP connect-src in index.html
// (test/static.test.js checks both).
//
// RPC: the keyless metashrew-backed JSON-RPC (operator brief). From a non-subfrost origin a browser cannot read it
// today (no Access-Control-Allow-Origin on the POST answer; lib/chain.js header has the measurement). Until the
// operator allows the Pages origin, the page shows that plainly and stops.
//
// JOURNAL
//  2026-11-25 created for fire-burn.

export const RPC_URL = 'https://mainnet.subfrost.io/v4/jsonrpc';
export const RPC_ORIGIN = 'https://mainnet.subfrost.io';
// Local canary mode (2026-11-25, measured with tlsfetch-curl): /v4/subfrost allowlists the dev
// origin http://localhost:3000 and answers it with Access-Control-Allow-Origin (it answers 0xcasuwu.github.io with
// 403 CORS_BLOCKED); it serves the same methods the page uses (metashrew_view, esplora_*, ord_outputs_batch,
// testmempoolaccept). Serving the page at http://localhost:3000 runs the operator canary before the Pages origin is
// allowed. Same RPC origin, so the CSP connect-src is unchanged. Its rate limit was not measured: the throttle stays.
export const LOCAL_DEV_ORIGIN = 'http://localhost:3000';
export const RPC_URL_LOCAL_DEV = 'https://mainnet.subfrost.io/v4/subfrost';
/** The RPC path for the page's own origin: the dev origin uses the allowlisted path, every other origin RPC_URL. */
export function rpcUrlFor(origin) { return origin === LOCAL_DEV_ORIGIN ? RPC_URL_LOCAL_DEV : RPC_URL; }
/** metashrew_view requests per minute (server limit 20 on this path; keep headroom). */
export const VIEW_CALLS_PER_MINUTE = 18;
export const EXPLORER_TX = 'https://mempool.space/tx/';
