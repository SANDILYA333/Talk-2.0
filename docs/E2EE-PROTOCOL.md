# S1: Frozen schema and protocol (E2EE v1 and v2)

This is a decision doc with no crypto code. Approve it or change it **before** S2. Once frozen, every later stage builds to it. Commit the approved version as `docs/E2EE-PROTOCOL.md`. 🪨

## 0. One flow tweak
- **v1 (2a):** run X3DH **per message, with no session and no ratchet**. Each message carries a fresh ephemeral key. Stateless, so there's no multi-tab race.
- **v2 (2b):** the same X3DH runs **once** to start a session, one-time prekeys are added, and the Double Ratchet takes over.
- Result: S2's X3DH code is reused in v2, not thrown away. S8 becomes "switch to sessions + OPKs".

## 1. Fixed choices

| Item | Decision |
|---|---|
| Curves and hashes | `@noble/curves` (X25519, Ed25519) and `@noble/hashes` (HKDF-SHA256, HMAC) |
| AEAD | AES-256-GCM via WebCrypto, 12-byte random nonce |
| Identity | Existing X25519 key `IK`. Add Ed25519 signing key `SIK`. |
| Binding | `SIK` signs `IK`. The safety number moves to `talk-safety-v2` and hashes **both** keys, and the client pins both. |
| Devices | **One device per account.** A new device means identity reset and old history is lost. |
| Private key storage | Raw bytes in IndexedDB for now. Passphrase wrapping comes in Phase 6. |
| Fail mode | **Fail closed.** Any error shows an error state, never plaintext or garbage. |

## 2. Key set

| Key | Type | Lives | Notes |
|---|---|---|---|
| `IK` | X25519 | long-term | already exists |
| `SIK` | Ed25519 | long-term | new, signs prekeys and `IK` |
| `SPK` | X25519 | rotate every 7 days | signed by `SIK` |
| `OPK` | X25519 | one-time, batch of 50 | used from v2 on |
| `EK` | X25519 | per message (v1) or per session start (v2) | throwaway |

Old `SPK` privates stay on the client for 30 days so late messages still decrypt.

## 3. Message schema (`Message`)

| Field | Type | Rule |
|---|---|---|
| `senderId`, `receiverId` | ObjectId | existing |
| `cid` | String | client UUID, unique per sender (dedupe and optimistic UI) |
| `v` | Number | `1` or `2`. Server rejects anything else. |
| `type` | `"text"` / `"media"` / `"secret"` | visible to server (accepted leak) |
| `ciphertext` | String (b64) | max 16 KB |
| `nonce` | String (b64) | exactly 12 bytes |
| `header` | Object | shape depends on `v` (section 4) |
| `expiresAt` | Date, optional | visible to server, needed for TTL delete |
| timestamps | | existing |

**Removed:** `text`, `image`, `video`. Media details live **inside** the ciphertext.

**Indexes:**
- Keep the two compound `_id` indexes.
- Add a unique `{senderId:1, cid:1}`.
- Add a TTL `{expiresAt:1}` with `expireAfterSeconds: 0` and `sparse: true`.

**Legacy data:** wipe dev messages before S5. The server rejects any send without `v >= 1`.

## 4. Wire headers

```
v1 header: { ek, spkId }
v2 header: { ek?, spkId?, opkId?, dh, n, pn }
```
- `ek`, `spkId`, `opkId` appear **only on the first message** of a v2 session.
- `dh` is the sender's current ratchet public key. `n` is the message number and `pn` is the previous chain length.
- All keys are base64, 32 bytes. Ids are integers.

## 5. Crypto definitions

**X3DH** (A = sender, B = recipient):
```
DH1 = DH(IK_A,  SPK_B)
DH2 = DH(EK_A,  IK_B)
DH3 = DH(EK_A,  SPK_B)
DH4 = DH(EK_A,  OPK_B)      // v2 only, if an OPK was served
SK  = HKDF-SHA256(salt = 32 zero bytes,
                  ikm  = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4],
                  info = "talk/x3dh/v1")
```
**v1 key:** `HKDF(SK, info="talk/v1/aead")`, 32 bytes.

**v2:** `SK` becomes the root key. Follow the Signal spec: a root KDF, chain keys via HMAC-SHA256 with constants `0x01` and `0x02`, and `MAX_SKIP = 100`.

**AEAD associated data** (stops the server re-aiming a message):
```
"talk/v" || v || type || senderId || receiverId || IK_A || IK_B
```

**Plaintext envelope** (before encryption): JSON `{ t, body, ts, replyTo?, att? }`, padded with `0x80 00…` to a multiple of 256 bytes. Text is capped at 4000 chars.

**Prekey verification, before the client uses any bundle:**
- Verify `SIK` over `"talk-spk-v1" || spkId || spkPub`.
- Verify `SIK` over `"talk-ik-v1" || IK`.
- If either fails, abort and show "can't verify keys".
- Also compare with the pinned keys. A change shows the red banner from G0.

## 6. Server key storage

**`KeyBundle`** (one per user):
```
userId (unique), sik, ikBinding (sig),
spk: { id, pub, sig, createdAt }, protoMax (1 or 2)
```
`IK` is **not** copied. It stays on `User.publicKey`.

**`OneTimePrekey`:** `{ userId, id, pub }`, unique on `(userId, id)`, max 100 per user.

**Endpoints:**

| Method and path | Purpose |
|---|---|
| `PUT /api/keys/bundle` | upload or rotate `SIK`, binding, `SPK` |
| `POST /api/keys/opks` | add OPKs (refill when fewer than 10 remain) |
| `GET /api/keys/opks/count` | own remaining count |
| `GET /api/keys/bundle/:userId` | fetch someone's bundle, atomically consuming one OPK (`findOneAndDelete`) |
| `POST /api/messages/send/:id` | `{cid, v, type, ciphertext, nonce, header, expiresIn?}` |

**Server rules:**
- Rate-limit bundle fetch to 20/min per user. This stops OPK drain attacks.
- Validate base64, lengths and sizes per `v`.
- Reject with `409 recipient-no-keys` if the recipient has no bundle.
- Use `protoMax` for negotiation: sender uses `min(own max, recipient max)`.
- The server **never decrypts, logs or stores plaintext**.

## 7. Client storage (IndexedDB)

```
identity:<uid>        IK + SIK (pub + priv)
spk:<uid>:<id>        SPK privates
opk:<uid>:<id>        OPK privates (v2)
session:<uid>:<peer>  ratchet state (v2, writes inside navigator.locks)
plain:<uid>:<msgId>   decrypted cache {body, ts, ...}
contact:<uid>:<peer>  pinned keys + verified flag (from G0)
```
- **Decrypted cache is required.** Ratchet keys are single-use, so you can't re-decrypt in v2. It also gives the chat list its snippets.
- **Sender can't decrypt their own sent messages** from the server blob. The sender's plaintext is cached at send time, so history is device-local.
- Until Phase 6, the cache is plaintext in IndexedDB. That's an accepted, documented gap.

## 8. Receive states (every message ends in exactly one)

`ok` · `waiting-for-key` · `undecryptable` (no key or new device) · `tampered` (tag fail) · `key-changed` · `unsupported-version`

## 9. Out of scope for S1 (on purpose)
Groups, multi-device, receipts, sealed sender, and server-side search. Unread counts are decided in S6.

## 10. Your approvals
Reply with **"approve all"**, or change any of these:

1. **v1 stateless X3DH per message**, session and ratchet in v2 (recommended)
2. **Separate Ed25519 `SIK`**, with the safety number covering both keys (recommended)
3. **One device per account**, with history loss on reset
4. **Raw-byte private keys now**, wrapping in Phase 6. This is the honest gap. Non-extractable keys can't be used with noble.
5. **Local-only history for the sender**, with no encrypt-to-self copy
6. **`type` and `expiresAt` visible to the server**

Heads-up: I can't prove this design is safe. It follows the Signal spec, but a crypto review is worth asking for before you call it production-grade. In interviews, say "implemented to the Signal spec, using vetted primitives, with test vectors." 🚀

After "approve all" comes **S2**: the crypto core as pure functions with tests written first.

## Amendments (S1.1)

### A. Canonical byte encodings
- u32be(n): 4-byte big-endian unsigned integer.
- ids (senderId, receiverId): 24-char lowercase hex string, UTF-8 (24 bytes).
- type codes: text=1, media=2, secret=3 (single byte).
- All keys: raw 32 bytes in signed/hashed inputs, base64 on the wire.

### B. Signature messages
- SPK sig:     SIK signs  utf8("talk-spk-v1") || u32be(spkId) || spkPub(32)
- IK binding:  SIK signs  utf8("talk-ik-v1")  || IK(32)

### C. AEAD associated data (replaces the string form in section 5)
AAD = utf8("talk/aad/v1") || u8(v) || u8(typeCode)
      || utf8(senderId)(24) || utf8(receiverId)(24)
      || IK_sender(32) || IK_receiver(32)
All fields after the label are fixed width, so no delimiter ambiguity.

### D. Identity upgrade for existing users
Stored record identity:<uid> keeps IK (publicKey, secretKey, base64).
Add field sik: { pub, priv } (base64) in place. Never regenerate IK.
Upgrade runs once at login if sik is missing.

### E. Key libraries
Existing tweetnacl X25519 keys are valid noble X25519 keys (raw 32 bytes).
No IK migration. New code uses @noble/curves and @noble/hashes only.

### F. Scope notes
- Sidebar preview comes from the client plaintext cache, fallback
  "Encrypted message".
- S5 is text only. Media UI is disabled until S7.
- Legacy dev messages are wiped by script before S5.
- talk-safety-v2 ships in S4 with SIK upload; verified flags reset once.

## Amendments (S1.2)
- GET /api/keys/bundle/:userId consumes a one-time prekey ONLY when
  query opk=1. Default: no OPK in the response (opk: null).
- GET /api/keys/bundle/:userId returns 404 {message:"recipient-no-keys"}
  when the user has no identity or no bundle; 400 for own id or bad id;
  409 "recipient-keys-stale" if the stored IK binding no longer verifies
  against User.publicKey. Response never contains email.
- Response: { userId, ikPub, sikPub, ikBinding, spk:{id,pub,sig},
  opk:{id,pub}|null, protoMax }. ikPub comes from User.publicKey.
- PUT /api/keys/bundle body { sik, ikBinding, spk:{id,pub,sig},
  protoMax? (1|2, default 1) }. Server verifies ikBinding over the
  CURRENT User.publicKey and spk.sig, using canonical base64 and exact
  lengths (32/64). spk.id: integer 1..2^32-1.
  Same sik: id must be > stored id, or == with identical pub (idempotent).
  Different sik (identity reset): accepted, all of the user's OPKs deleted.
- POST /api/keys/opks { keys:[{id,pub}] } 1..100 per call, max 100
  stored per user. Same id + same pub = skipped (idempotent). Same id +
  different pub = 409 "opk-conflict". Over cap = 409 "opk-cap".
  Needs an existing bundle (else 409 "no-bundle").
- GET /api/keys/opks/count -> { count }.
- PUT /api/identity with replace:true and a CHANGED publicKey deletes the
  user's KeyBundle and OneTimePrekeys.
- GET /api/identity/key/:userId additionally returns sik (null if no
  bundle yet).
- Rate limits: bundle fetch 20/min per user; bundle PUT and OPK POST
  30/min per user.
- Safety number v2: prefix "talk-safety-v2"; each party is
  IK(32)||SIK(32); the two 64-byte blobs are sorted bytewise; digest
  SHA-512; 12 groups of 5 digits as in v1.
- Pinned contact record: { ik, sik, verified }. Legacy { key, verified }
  is read as ik=key, sik=null. On first sight of a peer's sik the record
  is upgraded and verified resets to false (UI says the format changed).
  A peer with no sik yet has status "no-keys" and nothing is pinned.

## Amendments (S1.3) - Encrypted media
- `type: "media"` is accepted, with a required `blobId` (string, strict pattern, e.g. alphanumeric/hex/uuid 16-64 chars). `blobId` is forbidden on text.
- Media envelope: `{ t:"media", body?: caption, ts, att:{ kind, mime, size, w, h, dur?, url, key, nonce, ph } }`.
- Blob AAD is the label `talk/blob/v1`. The decrypted length must equal `att.size`.
- The plaintext cache record also stores `att` (backward compatible with S5 records).
- Storage file: Random 128-bit name, no extension, no original filename.
- Direct browser-to-ImageKit upload using short-lived signed params from `GET /api/media/upload-auth`.
- Provider swap: All blob I/O goes through `blobStore` interface.

## Amendments (S1.4) - v2 Sessions (S8)

### 1. Initiator (Handshake & Key Derivation)
- Fetches peer's bundle with query parameter `?opk=1`.
- Verifies peer's prekey bundle (`SIK` over `SPK`, `SIK` over `IK`, and pinned contact comparison).
- Generates ephemeral keypair `EK_A`.
- Computes X3DH agreement:
  - `DH1 = DH(IK_A,  SPK_B)`
  - `DH2 = DH(EK_A,  IK_B)`
  - `DH3 = DH(EK_A,  SPK_B)`
  - `DH4 = DH(EK_A,  OPK_B)` (only if an OPK was returned in the bundle)
  - `SK  = HKDF-SHA256(salt = 32 zero bytes, ikm = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4], info = "talk/x3dh/v2/session")`
- Initial symmetric chain keys derived from `SK`:
  - `CK_send = HKDF-SHA256(SK, salt = 32 zero bytes, info = "talk/v2/chain/init-send")`
  - `CK_recv = HKDF-SHA256(SK, salt = 32 zero bytes, info = "talk/v2/chain/init-recv")`
- Fallback: if OPK is absent (null/exhausted), 3-DH fallback is executed without DH4.

### 2. Initial Message Header
- Carries initial handshake fields in `header`:
  - `sessionId`: unique session string identifier (16 bytes random hex or UUID).
  - `n`: message sequence counter (starts at `0`).
  - `ek`: base64-encoded `EK_A` public key (32 bytes).
  - `spkId`: recipient's SPK id (integer).
  - `opkId`: recipient's OPK id (integer or `null` if OPK was absent).
  - `ik`: initiator's `IK_A` public key (32 bytes base64).
  - `sik`: initiator's `SIK_A` public key (32 bytes base64).
- Subsequent messages in an established session send only:
  - `sessionId`: string.
  - `n`: message sequence counter (integer).

### 3. Responder (Verification, Handshake & One-Time Deletion)
- Validates initial header fields (`ek`, `spkId`, `opkId`, `ik`, `sik`).
- Looks up `SPK_B` private key by `spkId` from local store (must be active or within 7-day grace period).
- If `opkId` is provided, fetches and atomically deletes `OPK_B` private key (`takeOpkPriv`). If `opkId` is unknown or already consumed, rejects closed with error (replay protection).
- Verifies initiator's `SIK` signature over `IK_A`. Compares against pinned contact record; if changed, aborts with `key-changed`.
- Recomputes identical `SK`:
  - `DH1 = DH(SPK_B, IK_A)`
  - `DH2 = DH(IK_B,  EK_A)`
  - `DH3 = DH(SPK_B, EK_A)`
  - `DH4 = DH(OPK_B, EK_A)` (if `opkId` was present)
  - `SK  = HKDF-SHA256(...)`
- Initial symmetric chain keys (inverts send/recv from initiator):
  - `CK_send = HKDF-SHA256(SK, salt = 32 zero bytes, info = "talk/v2/chain/init-recv")`
  - `CK_recv = HKDF-SHA256(SK, salt = 32 zero bytes, info = "talk/v2/chain/init-send")`
- Atomically creates the session record in IndexedDB in the same transaction as OPK deletion.

### 4. Session Record in IndexedDB (`session:<uid>:<peerId>`)
- Schema:
  - `peerId`: string.
  - `sessionId`: string.
  - `role`: `"initiator"` | `"responder"`.
  - `sk`: Uint8Array (32 bytes).
  - `chainKeySend`: Uint8Array (32 bytes).
  - `chainKeyRecv`: Uint8Array (32 bytes).
  - `sendCounter`: integer (starts at 0).
  - `recvCounter`: integer (starts at 0).
  - `peerIk`: string (base64).
  - `peerSik`: string (base64).
  - `createdAt`: integer (timestamp ms).
  - `state`: `"pending"` | `"established"`.
  - `skippedKeys`: Map or Record `{ [counter: number]: { key: string (b64), createdAt: number } }`.

### 5. Message Format v2
- `v`: `2`.
- `type`: `"text"` | `"media"` | `"secret"`.
- `cid`: client-generated UUID.
- `header`: initial message fields or established session header (`{ sessionId, n }`).
- `ciphertext`: base64 ciphertext of padded JSON envelope.
- `nonce`: 12-byte random AES-GCM IV.
- `AAD`:
  ```
  AAD = utf8("talk/aad/v2") || u8(v) || u8(typeCode)
        || utf8(senderId)(24) || utf8(receiverId)(24)
        || IK_sender(32) || IK_receiver(32)
        || utf8(sessionId) || u32be(n)
  ```
  Binds the ciphertext to version, type, sender, receiver, identity keys, session ID, and counter `n`.

### 6. Per-Message Key & Symmetric Chain
- Signal-style symmetric KDF ratchet:
  - Per-message key: `Mk = HMAC-SHA256(CK, 0x01)` (32 bytes).
  - Next chain key: `CK_next = HMAC-SHA256(CK, 0x02)` (32 bytes).
- Each message is encrypted with `Mk` and a fresh 12-byte random nonce.
- `Mk` is never reused and is securely erased from memory after encryption/decryption.

### 7. Out-of-Order Handling & Replay Protection
- Maximum skip window: `MAX_SKIP = 100`.
- If receiving `n > Nr`:
  - If `n - Nr > MAX_SKIP`, reject immediately (fail closed, state unchanged).
  - If `n - Nr <= MAX_SKIP`, advance `CK_recv` step-by-step from `Nr` to `n - 1`, storing derived keys in `skippedKeys[step] = { key: toB64(Mk), createdAt: Date.now() }`.
  - Update `Nr = n + 1`.
  - Decrypt with message key derived at index `n`.
- If receiving `n < Nr`:
  - Check `skippedKeys[n]`.
  - If found: decrypt with stored key, then delete `skippedKeys[n]` immediately.
  - If not found: reject message as duplicate/replayed (fail closed).

### 8. Simultaneous Initiation (Race Resolution)
- If both parties initiate a session concurrently (both send initial messages before receiving one):
  - Compare initiator identity keys `IK_A` and `IK_B` lexicographically (bytewise).
  - The session whose initiator has the lower `IK` wins and becomes the active primary session.
  - The losing session is archived in a read-only secondary slot (`session-loser:<uid>:<peerId>`) for 7 days to decrypt any in-flight messages sent under it, after which it is pruned.

### 9. SPK Rotation Grace Period
- Active SPK rotates every 7 days.
- Retired SPK private keys are kept in client IndexedDB (`spk:<uid>:<id>`) for a 7-day grace period (`SPK_ROTATE_MS`) before deletion, ensuring late or in-flight initial messages decrypt successfully.

### 10. OPK Replenishment
- Client checks remaining OPK count via `GET /api/keys/opks/count`.
- When server count drops below 20 (`OPK_LOW_THRESHOLD = 20`), client generates 50 new OPKs (`generateOpks(uid, 50)`) and uploads them via `POST /api/keys/opks`.

### 11. Identity-Key Change Handling
- Pinned contact keys (`IK` and `SIK`) are checked before initiating or stepping any session.
- If peer's `IK` or `SIK` changes from the pinned record:
  - Block sending.
  - Mark session as `key-changed`.
  - Display user-visible safety number verification warning.
  - Never automatically accept key changes.

