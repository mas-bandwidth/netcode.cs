# netcode.cs — red team brief

You are attacking a C# port of the netcode protocol (the C reference lives at
`~/rowan-working/netcode`, protocol "NETCODE 1.02", spec in `STANDARD.md`). The
wire is claimed byte-identical to the C library and the crypto is claimed
constant-time and correct. Your job is to break those claims. This brief gives
you the surface, the claims, and how to run things — not the rationale.

## How to run

```sh
cd ~/rowan-working/netcode.cs
dotnet run --project tests/Tests.csproj -f net10.0            # full suite
dotnet run --project tests/Tests.csproj -f net10.0 -- <substr>   # one test
dotnet run --project tests/Tests.csproj -f net10.0 -- soak 100000
scripts/interop.sh ~/rowan-working/netcode                   # the interop gate
```

The library is `src/` (four files). Tests are `tests/`. Everything is `internal`
but visible to `Tests` and `Compat` via `InternalsVisibleTo`, so you can call
`Aead`, `PacketIO`, `ConnectTokenPrivate`, `ReplayProtection`, `EncryptionManager`
directly from a new test file without touching the library.

## Target #1 — the crypto (`src/Crypto.cs`)

Fully managed, hand-written ChaCha20 + Poly1305 + HChaCha20, composed into
`crypto_aead_chacha20poly1305_ietf` (packets, challenge tokens) and
`crypto_aead_xchacha20poly1305_ietf` (private connect token). No platform
crypto, no libsodium, in the production path. **This is the highest-value
target: a flaw here is a protocol break or a key/plaintext leak.**

Attack it:
- **Correctness at boundaries.** Poly1305 uses 44-bit limbs over `UInt128` with
  a hand-written final reduction and a constant-time "subtract p if ≥ p" step
  (`Poly1305Finish`). Hunt for a message length / AD length / limb-carry
  combination where the managed tag diverges from libsodium. The BCL
  differential (`test_crypto_differential_bcl`) only runs where
  `ChaCha20Poly1305.IsSupported`, and only covers the IETF AEAD with
  message ≤ 400 and AD ≤ 64 bytes — go wider, longer, and cover XChaCha (the
  BCL has no XChaCha oracle at all; XChaCha is pinned ONLY by one KAT and the
  interop gate). Consider block-boundary lengths (0, 16, 63, 64, 65, 1200),
  empty AD vs empty message, and the counter rollover in `ChaCha20Xor` for
  long inputs.
- **The ChaCha20 counter.** `EncryptIetf` starts the stream at counter 1
  (Poly1305 key is counter 0). Verify that is right for every input size and
  that `state[12]++` per block cannot alias the Poly1305 key block.
- **HChaCha20** (`Crypto.cs`, the XChaCha subkey): outputs words 0..3 and 12..15
  with NO final addition. Check that against the spec — a wrong slice silently
  weakens the connect-token key derivation without failing a round-trip test.
- **Constant-time claims.** Tag compare is `FixedTimeEquals`. `Poly1305Finish`'s
  reduction is claimed branch-free. Look for any secret-dependent branch or
  early-out, any `if` on key/tag/plaintext bytes.
- **Decrypt ordering.** `DecryptIetf` computes the tag and returns false WITHOUT
  touching the buffer if it mismatches — plaintext must never be produced for a
  bad tag. Try to find a path that writes plaintext before/despite auth failure,
  or that leaves partial plaintext in the caller's buffer on failure.

## Target #2 — packet parsing (`PacketIO.ReadPacket`, `src/Netcode.cs`)

Every byte off a socket goes through here. The claim: it follows the exact
validation order in STANDARD.md ("Reading Encrypted Packets") and never throws,
never reads out of bounds, never accepts a forged packet.

Attack it:
- Truncations at every field boundary (1 byte, `1 + seqbytes`, `1 + seqbytes +
  15`, connection-request that is 1077 or 1079 bytes).
- Prefix byte fuzzing: sequence-byte nibble 0 and 9..15, packet type 7..15,
  every disallowed type per direction (client must reject request/response;
  server must reject challenge).
- The variable-length sequence decode (`1..8` bytes, reversed) vs the nonce it
  builds — a mismatch is an auth bypass or a wrong-nonce accept.
- Decrypted-size checks per type (0 for denied/disconnect, 8 for keep-alive,
  `8+300` for challenge/response, `1..1200` for payload). Try to smuggle a
  wrong-sized decrypted body through.
- `test_fuzz_read_packet_raw` and `test_fuzz_packet_round_trip_corruption` in
  `tests/Hostile.cs` are the existing sweeps (20000 + 2000 iterations, seeded).
  Reseed, widen, and push iteration counts up. Any accepted-when-corrupt or any
  throw is a finding.

## Target #3 — the parse paths off connect tokens and addresses

- `ConnectTokenData.Read` / `ConnectTokenPrivate.Read` (public/private tokens):
  address-count bounds `[1,32]`, address-type validation, `create <= expire`,
  exact-length requirement for the public token. `test_fuzz_connect_token`
  covers these; extend it.
- `Address.TryParse` (`src/Netcode.cs`): reproduces the C parser's quirks,
  including the deliberately-lenient `[::1` (unterminated bracket parses as
  `::1`) and strict decimal ports in `[0,65535]`. It must never throw and must
  round-trip through `ToString`. `test_fuzz_parse_address` replays the C fuzz
  corpus (`~/rowan-working/netcode/fuzz/corpus/fuzz_parse_address`) plus 20000
  seeded strings. Look for a parse that succeeds but does NOT match the C
  library's `netcode_parse_address` on the same input — that is a wire/behavior
  divergence even though neither throws. The interop harness does not currently
  cross-check address parsing byte-for-byte; that is a gap you can exploit or
  formalize.

## Target #4 — replay protection & nonce discipline

- `ReplayProtection` (`src/Netcode.cs`): the overflow-safe already-received test
  (`most_recent >= SIZE && sequence <= most_recent - SIZE`) and the rule that
  the window advances ONLY after authentication, only for packet types ≥ 4.
  `test_replay_protection` pins the near-`UInt64.MaxValue` behavior. Try to make
  it either accept a replay or reject a fresh packet.
- The server global sequence starts at `2^63` on every `Start` (see
  `test_server_restart_global_sequence`). If you can make a global packet
  (challenge/denied) and a per-client packet share a nonce under the same
  server-to-client key within one run, that is a nonce-reuse break. The stop→start
  reseed is the guard; attack the reseed.

## Target #5 — the state machines (`Client.cs`, `Server.cs`)

Ported line-for-line from `netcode.c`. Compare against it. Candidate divergences
to probe:
- Connection-request processing order in `Server.ProcessConnectionRequestPacket`
  (must match STANDARD.md §"Processing Connection Requests" exactly — including
  that the token single-use entry is added only after the address/id/whitelist
  checks pass and BEFORE the challenge is sent).
- Client timeout uses `last_receive + timeout < time`; server uses `<= time`.
  These differ in the C source and are ported as-is — verify the port kept the
  asymmetry (a "fix" here would be a bug).
- `should_disconnect` latch → try next server address before entering an error
  state; connect-token-expiry measured as `time - connect_start >= (expire -
  create)`.
- The encryption-mapping expiry/`client_index` interplay in `EncryptionManager`
  (add/remove/find, the trailing-entry compaction in `RemoveEncryptionMapping`).

## Wire claims to try to falsify

1. Every token and packet golden is byte-identical to the C library
   (`scripts/interop.sh` leg 1, 10 files). Find an input class not covered by
   the fixed goldens where the two diverge — e.g. an IPv6-heavy token, a
   maximum-address-count token, a sequence number needing a different byte
   count, a zero-length vs max-length payload.
2. Each side decrypts and parses the other's output (leg 2).
3. C client ↔ C# server and C# client ↔ C server complete a full
   connect/exchange/disconnect (legs 3–4). These run one client, one payload
   size, clean disconnect. Attack with: multiple clients, server-full denial,
   timeout-driven disconnect, the second-server-address fallback, dual-stack.

## Invariants the tests assert (so you know what's already covered)

- KAT crypto goldens (both AEADs) + tamper rejection + BCL differential.
- All 7 packet types round-trip; wrong sizes/types/truncations rejected.
- Replay window correctness including the `UInt64.MaxValue` neighborhood.
- Encryption manager add/remove/find/timeout/expire.
- Every client error state; client- and server-side disconnect; disconnect
  reason recorded before the callback; reconnect; disable-timeout; loopback.
- Zero allocation on the connected steady-state packet path
  (`test_zero_allocation_steady_state`, `GC.GetAllocatedBytesForCurrentThread`
  over 2000 warm frames == 0). Try to make a steady-state path allocate.
- Deterministic network simulator reproducibility.

## Known gaps (not gold-plating these; go here first)

- The BCL crypto differential does not cover XChaCha20 (no platform oracle) and
  caps message/AD sizes — XChaCha correctness rests on one KAT + the interop
  gate. **Widen this.**
- Address parsing is not cross-checked byte-for-byte against the C parser in the
  interop harness — only self-consistency (parse→ToString→parse) is tested.
- The interop live sessions are single-client, single-payload-size, clean
  disconnect. Multi-client and adverse-path cross-implementation sessions are
  untested across the language boundary.
- Windows packet tagging is a no-op (documented); the socket layer is only
  exercised on Linux/macOS in CI.
