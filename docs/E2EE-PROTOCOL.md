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
