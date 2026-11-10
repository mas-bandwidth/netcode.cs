# Post-release hardening — netcode.cs

From the 2026-08-07 red/blue security review of v1.0.0 (five adversarial
lenses, two independent cryptography passes under different models). Verdict
was **READY** — zero surviving findings after adversarial refutation. Fixes made
since that review are in the git log (v1.1.0 and later). The items below were
recorded as defense-in-depth follow-ups, none a release blocker; each says what
the code does at this revision.

1. **Long-lived key material.** The code clears key material on the paths below
   (covered by `test_key_cleanup`). Each path names the call it uses:
   - `Server.Stop` (also run by `Server.Dispose`) clears `_challengeKey` with
     `Array.Clear`, then calls `EncryptionManager.Reset`, which clears the
     `SendKey` and `ReceiveKey` arrays with `CryptographicOperations.ZeroMemory`.
     `RemoveEncryptionMapping` and unowned `EntryExpired` entries clear that
     mapping's keys with `CryptographicOperations.ZeroMemory`. `Server.Dispose`
     clears `_privateKey` with `CryptographicOperations.ZeroMemory`.
   - The client's `ResetConnectionData`, run whenever the client leaves a
     connecting or connected state (`Disconnect`, timeouts, token expiry,
     denial, server disconnect, `DisconnectLoopback`; `Dispose` disconnects
     first), clears the read/write packet keys with `Array.Clear`.
     `ClearConnectToken`, which it calls, clears `_connectToken.PrivateData`
     and both connect-token keys with `Array.Clear`.
   - `ConnectTokenGenerator.Generate` clears the temporary private buffer and
     the `ConnectTokenPrivate` and `ConnectTokenData` key arrays with
     `CryptographicOperations.ZeroMemory`. `Server.ProcessConnectionRequestPacket`
     clears the decrypted private keys and the connection-request payload with
     `CryptographicOperations.ZeroMemory`. The crypto clears its ephemeral
     subkey, keystream and Poly1305 key with `CryptographicOperations.ZeroMemory`.
   What remains: copies the GC made while moving heap arrays before they were
   cleared cannot be cleared by the library.

2. **Give the socket layer a dedicated review pass.** `NetcodeSocket`, the
   `NetworkSimulator`, and the loopback client/server paths sit off the
   on-the-wire crypto/parse trust boundary and were not line-diffed against the
   C. They have changed since (for example `NetcodeSocket.ReceivePacket` now
   polls for readability), but no dedicated review pass is recorded.

3. **Differential vectors run live** — satisfied: the `C wire compatibility` CI job
   builds the real `netcode.c` and requires byte-identical goldens both directions
   on every push to `main` or a `sprint/*` branch and on every pull request. Keep it green; it is the proof under the READY verdict.
