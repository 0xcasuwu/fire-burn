# FIRE burn

A single static page that burns FIRE from your own browser wallet. It calls the FIRE token
(`2:77623`) opcode 88 **Burn**, which removes the FIRE it receives from the total supply. Everything
else on the coins you spend comes back to your own address. **A burn cannot be undone.**

No build step, no dependencies, no analytics, no storage. Vanilla JavaScript and Web APIs only.

## How a burn transaction looks

| | |
|---|---|
| inputs | your FIRE coin(s), then plain-BTC fee coin(s) |
| output 0 | your FIRE address, 600 sats: the FIRE you keep and every other alkane on those coins |
| output 1 | BTC change to your fee address (left out when it would be dust) |
| output 2 | `OP_RETURN` Runestone (tag 16383) with two protostones |
| p0 | edict: exactly N FIRE to p1; pointer and refund are output 0 |
| p1 | call `[2, 77623, 88]`; pointer and refund are output 0, so a failed call refunds you |

Why two protostones: the alkanes indexer hands every input alkane to the first protostone. A single
protostone carrying the call would burn your whole FIRE coin. p0 splits off exactly N first. This is
the same layout the SUBFROST app uses for every FIRE action.

## What is checked before your wallet is asked anything

1. FIRE answers name and symbol `FIRE`. Its max supply confirms 8 decimals. The contract behind the
   `2:77623` proxy is an implementation whose `burn()` was reviewed, with matching bytecode sha256.
2. Every coin is read one outpoint at a time, all at one block height. Fee coins must carry no alkanes,
   no inscriptions and no runes. If any of that can't be checked, the coin is not used.
3. The amount is greater than zero and no more than your balance. It is shown in base units too.
4. The built transaction is decoded from its own bytes. Every pointer must land on output 0, and the
   indexer's routing is replayed. A live simulation must consume exactly N, accept a burn of the whole
   supply and refuse supply + 1.
5. You type the amount to unlock signing. Right before the wallet prompt, and again before
   broadcasting, the page re-reads which implementation FIRE runs. The signed transaction must have the
   txid that was built, and every signature must cover the whole transaction. The node must accept it in a
   dry run (`testmempoolaccept`). Broadcasting takes a second click.

## Wallets

SUBFROST Wallet (extension), UniSat, OYL, Xverse and Leather, through their injected providers. Taproot
and native SegWit coins work, plus P2SH-wrapped SegWit for the fee address. The SUBFROST Wallet
needs a fee rate of at least about 1.25 sat/vB; below that its fee patch would rewrite the transaction, so
the page refuses before the popup. Fee rates are limited to 1–300 sat/vB and fees to 100,000 sats.

## Run locally

```sh
python3 -m http.server 3000 --bind 127.0.0.1    # then open http://localhost:3000 (uses /v4/subfrost, which allows that origin)
npm test                                         # node --test, built-ins only
node scripts/sri.js                              # after editing app.js or style.css
node scripts/live-check.js <bc1p…> 0.00000001 2  # read-only mainnet rehearsal for any FIRE address
node scripts/canary-verify.js <txid> <amount>    # read-only proof of a confirmed burn
```

The page reads `https://mainnet.subfrost.io/v4/jsonrpc` (see `lib/config.js`). The browser must be
allowed to read that RPC from the page's origin. If it isn't, the page says so and stops.

## Operator canary (before announcing the page)

1. Confirm the RPC lets the Pages origin read its answers. The page's status line must say "RPC reachable".
2. Use a wallet that holds a small FIRE balance on a confirmed coin, and a separate confirmed BTC coin
   of at least 5,000 sats.
3. Connect. Check the token panel shows `2:77623 · FIRE / FIRE`, decimals 8 and implementation `4:512`
   (or `4:548` once FIRE v3 is switched on).
4. Enter `0.00000001` (1 base unit) and a fee rate at or above the next-block estimate. Click Build and check.
5. Read the review. It must say `burns 0.00000001 FIRE · returns <balance − 1 unit> FIRE … to <your FIRE
   address> · fee … sats`. Open "Decoded transaction" and check p0 has the edict `[2:77623, 1 → 5]`
   (or `→ 4` without change) and p1 the call `[2, 77623, 88]`, both pointing at output 0.
6. In the wallet popup, check the outputs are your own addresses plus one `OP_RETURN`. Sign.
7. The page must report that the node would accept it. Click Broadcast and keep the txid.
8. After one confirmation, run `node scripts/canary-verify.js <txid> 0.00000001`. It must print
   `CANARY VERIFIED`: shape OK, trace shows exactly 1 unit of FIRE in and SUCCESS, output 0 holds the rest
   of the FIRE, and supply dropped by at least 1.
9. Repeat once with a partial amount of real size and once with each wallet you intend to list as supported.

## Limits

- FIRE is only looked for on coins of 1,000 sats or less at your FIRE address. FIRE on a bigger coin
  isn't found, and such a coin is never used to pay fees.
- The keyless RPC path allows 20 `metashrew_view` calls a minute. The page paces itself, so wallets
  with many small coins take longer to scan.
- Unconfirmed coins are never used.
