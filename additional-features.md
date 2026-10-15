# 🚀 TALK — Feature Roadmap to Next-Level

10 features, ranked roughly by build order. Each one is scoped to be resume-defensible — meaning if an interviewer asks "how does this work," you have a real answer, not a buzzword.

---

## 1. Public-Key Connect ID (PII-Free Identity)

**What it does**
Replaces phone/email signup with a cryptographic identity. On first launch, the client generates a keypair; the user's identity becomes a short "Connect Code" derived from their public key, shareable via text or QR.

**What finish looks like**
A user opens TALK, sees a unique code like `TALK-8F2K-91XZ` and a QR version of it. Another user scans/enters it and a chat opens — no phone number, no email, no OTP screen anywhere in the flow.

**How it improves the app**
Kills spam at the root (codes can't be scraped or dialed), removes your single biggest compliance/privacy liability (storing phone numbers/emails), and is the exact pattern used by **Session Messenger** — a strong, specific talking point in interviews.

**How to implement it**
- Generate an X25519 keypair client-side using `tweetnacl` or the native `SubtleCrypto` API on signup.
- Hash + truncate the public key (Base32-encode ~8 bytes) to form the human-shareable code.
- Store the public key server-side keyed by code; private key **never leaves the device** (use IndexedDB, not localStorage).
- Add `react-qr-code` for QR generation and a scanner (e.g. `@yudiel/react-qr-scanner`) for import.

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"Show me how to generate an X25519 keypair in the browser with tweetnacl-js, derive a short Base32 identity code from the public key, and store the private key safely in IndexedDB for a React app."*
- **YouTube:** [React.js QR Code Tutorial](https://www.youtube.com/watch?v=njeaCPYuDIg)

---

## 2. Signal-Protocol E2E Encryption (Double Ratchet + Forward Secrecy)

**What it does**
Upgrades your encryption from basic E2E to Signal's Double Ratchet — every message uses a fresh key, so a single compromised key never exposes past or future messages.

**What finish looks like**
Two users chat normally; under the hood, each message is encrypted with a unique symmetric key derived from a constantly-updating ratchet, visible to you only in devtools/logs, invisible to the user.

**How it improves the app**
This is the single biggest jump from "an encrypted app" to "a *properly* encrypted app." It's the exact algorithm behind Signal, WhatsApp, and Messenger's secret chats — dropping this term correctly in an interview signals real cryptography understanding, not just "I called `crypto.encrypt()`."

**How to implement it**
- Start with X3DH for the initial key exchange (public key + one-time prekeys stored server-side).
- Implement the ratchet: a root key that advances on each Diffie-Hellman exchange, and a chain key that advances per-message.
- Use `libsodium-wrappers` or `noble-curves` for the underlying primitives — don't write raw crypto math yourself.
- Reference implementation architecture: [Adapting the Signal Protocol for P2P Messaging over WebRTC](https://positive-intentions.com/blog/p2p-signal-protocol/).

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"Walk me through implementing a simplified Double Ratchet algorithm in JavaScript using noble-curves — I want root key, chain key, and message key derivation with forward secrecy, for a MERN chat app."*
- **YouTube:** [Signal's Double Ratchet Algorithm — explained](https://www.youtube.com/watch?v=hHAC6oK1kPI)

---

## 3. Disappearing / Self-Destructing Messages

**What it does**
Messages auto-delete (client + server) after a timer the user sets — 1 hour, 1 day, 1 week, or "off."

**What finish looks like**
A small timer icon next to the message composer; sent messages show a subtle countdown or fade indicator before vanishing from both devices and your database.

**How it improves the app**
Cheap to build, immediately visible in a demo, and directly reinforces your "privacy-first" positioning — pairs naturally with the encryption work above.

**How to implement it**
- Store an `expiresAt` timestamp on each message document in MongoDB.
- Use a **TTL index** in MongoDB (`expireAfterSeconds`) so expired messages are auto-purged server-side — no cron job needed.
- On the client, run a `setInterval` to hide/remove expired messages from the UI before the server catches up.

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"Show me how to set up a MongoDB TTL index so chat documents auto-delete after a user-configurable expiry time, plus the Mongoose schema for it."*
- **YouTube:** No dedicated video for this specific combo — [MongoDB's official TTL index docs](https://www.mongodb.com/docs/manual/core/index-ttl/) are the fastest path.

---

## 4. Encrypted Local Storage (At-Rest Protection)

**What it does**
Encrypts the local message cache on-device, so a stolen laptop/phone or a leaked IndexedDB dump doesn't expose chat history.

**What finish looks like**
Functionally invisible to the user — chats load instantly as before — but inspecting the browser's storage shows only ciphertext.

**How it improves the app**
Closes the "what if someone steals my device" gap that pure E2E-in-transit doesn't cover. It's a small addition that shows you think about the *whole* threat model, not just the network layer.

**How to implement it**
- Derive a local encryption key from the user's device keypair (from Feature 1) using HKDF.
- Wrap IndexedDB reads/writes with `SubtleCrypto.encrypt`/`decrypt` (AES-GCM) before storing/after reading.
- Never store the derived key itself — regenerate it each session from the keypair.

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"Show me how to wrap IndexedDB writes and reads with AES-GCM encryption using the Web Crypto API, deriving the key via HKDF from an existing keypair, in a React app."*
- **YouTube:** [End-to-End Encrypted Chat with the Web Crypto API — explanation](https://www.youtube.com/watch?v=GSIDS_lvRv4)

---

## 5. Safety Number Verification (MITM Protection)

**What it does**
Lets two users compare a fingerprint (a short number/QR derived from both public keys) in person or over a trusted channel to confirm they're talking to who they think they are — not a server-in-the-middle.

**What finish looks like**
A "Verify Contact" screen showing a 12-digit number or QR; if it matches on both devices, the chat gets a small ✅ verified badge.

**How it improves the app**
This is what separates "encrypted" from "encrypted *and* authenticated" — exactly the distinction Signal makes with its safety numbers. Small feature, disproportionately impressive when explained correctly.

**How to implement it**
- Concatenate both users' public keys, hash with SHA-256, format as a 12-digit number (Signal does exactly this).
- Compare via QR scan (in person) or manual read-aloud (remote) — no server involvement, by design.

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"How does Signal generate its 'safety number' fingerprint from two users' public keys, and how would I implement the same hashing/formatting logic in JavaScript?"*
- **YouTube:** No dedicated tutorial exists for this specific feature — the [Signal Double Ratchet video above](https://www.youtube.com/watch?v=hHAC6oK1kPI) covers the underlying key concepts.

---

## 6. Sealed Sender / Metadata Minimization

**What it does**
Restructures your server so it can relay messages without knowing *who is talking to whom* — only that ciphertext moved from one socket to another.

**What finish looks like**
No visible UI change — this is a backend/architecture feature you'd explain via a diagram in your README, not something a user sees.

**How it improves the app**
Most "secure" chat apps still leak metadata (who messaged whom, when, how often) even with E2E content encryption. Fixing this is a genuinely advanced, resume-differentiating claim — very few student projects attempt it.

**How to implement it**
- Route messages through Socket.io using rotating anonymous session tokens instead of persistent user IDs.
- Encrypt the "envelope" (sender/recipient identifiers) separately from the message body, decryptable only by the recipient.
- Strip identifying fields from server logs entirely — log connection events, not identity-to-identity pairs.

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"Explain how Signal's 'sealed sender' feature hides the sender's identity from the server, and suggest an achievable simplified version for a Node.js/Socket.io chat backend."*
- **YouTube:** No direct tutorial — this is architecture-level; the [Signal sealed sender engineering blog post](https://signal.org/blog/sealed-sender/) is the best primary source.

---

## 7. Group Chats with Sender Keys

**What it does**
Extends your Double Ratchet (1-to-1) encryption to groups efficiently, using Signal's "Sender Key" scheme instead of encrypting each message individually per recipient.

**What finish looks like**
A group chat that feels identical to a 1-on-1 chat but scales to dozens of members without a linear slowdown per message.

**How it improves the app**
Naive group E2E (encrypting once per recipient) doesn't scale — implementing Sender Keys shows you understand *why* the naive approach fails and how production systems solve it.

**How to implement it**
- Each group member generates a "sender key" and distributes it 1-to-1 (via your existing Double Ratchet) to every other member once.
- Messages are then encrypted once with the sender key and broadcast — recipients decrypt using the sender key they already hold.
- Rotate the sender key whenever someone leaves the group (forward secrecy for group membership changes).

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"Explain Signal's Sender Key algorithm for group messaging encryption and outline how I'd implement key distribution and rotation in a Node.js/Socket.io group chat feature."*
- **YouTube:** No dedicated video found — the [Signal technical documentation](https://signal.org/docs/) is the primary reference.

---

## 8. E2E Encrypted Voice & Video Calls (WebRTC)

**What it does**
Adds real-time voice/video calling, signaled through your existing Socket.io server but transmitted peer-to-peer (so the server never touches the actual audio/video stream).

**What finish looks like**
A call button on any chat that opens a video/audio call UI — connects in a couple seconds, works cross-network via a TURN server fallback.

**How it improves the app**
This is the feature that makes TALK look like a "real" competitor to Signal/WhatsApp rather than a text-only demo. It's also just genuinely fun to show off in an interview.

**How to implement it**
- Use `simple-peer` (wraps raw WebRTC) for peer connection management.
- Socket.io handles only the signaling handshake: offer → answer → ICE candidates.
- Add a free/self-hosted STUN/TURN server (e.g. `coturn`) so calls work behind restrictive NATs.

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"Walk me through adding WebRTC video calling to an existing MERN + Socket.io chat app using simple-peer, including signaling events and a basic call UI in React."*
- **YouTube:** [How to Create a ReactJS Video Chat App with WebRTC and Socket.io](https://www.youtube.com/watch?v=gnM3Ld6_upE)

---

## 9. Offline Local Mesh Messaging (Bitchat-Style)

**What it does**
Lets nearby devices exchange messages directly over Bluetooth/local WebRTC when there's no internet connection at all — the actual feature Bitchat is known for.

**What finish looks like**
A "Nearby" mode toggle; in a room with no wifi, two phones running TALK can still discover each other and chat, syncing to the cloud once internet returns.

**How it improves the app**
This is your single highest-impact, hardest-to-fake feature. Almost no student chat app attempts offline mesh — it's the one line on your resume that will make an interviewer say "wait, you built *what*?"

**How to implement it**
- Start with `navigator.bluetooth` (Web Bluetooth API) for device discovery/pairing on supported platforms (Chrome/Android; note Safari/iOS doesn't support it — be upfront about this limitation).
- Exchange your existing E2E-encrypted message payloads directly over the Bluetooth GATT characteristic instead of Socket.io.
- Queue messages locally and sync to MongoDB once the device regains internet — treat "online" and "offline" as just two different transports for the same encrypted payload.

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"Explain how to use the Web Bluetooth API to discover nearby devices and exchange small encrypted text payloads directly between two browsers, without an internet connection."*
- **YouTube:** [Connect Bluetooth Devices using JavaScript](https://www.youtube.com/watch?v=XWfkchrBztc)

---

## 10. Silent Encrypted Push Notifications

**What it does**
Sends push notifications ("New message from ***") without the push provider (or your own server) ever seeing the actual message content.

**What finish looks like**
User gets a notification like "New message" (not the content) while the app is closed; opening the app decrypts and shows the real text.

**How it improves the app**
Most apps leak message previews to the push provider (Apple/Google servers technically see plaintext notification content). Avoiding that is a small, specific, provably-correct privacy claim you can make in an interview.

**How to implement it**
- Use the Web Push API with VAPID keys, but send only a generic placeholder as the payload — never the real message.
- On receiving the push event in your service worker, wake the app and pull the actual encrypted message from your backend, decrypting client-side before displaying.

**Resources**
- **OpenAI / Claude / Gemini prompt:** *"Show me how to implement Web Push notifications with a service worker and VAPID keys in a React app, where the push payload only contains a generic placeholder and the real message is fetched and decrypted separately."*
- **YouTube:** [Push Notifications with Service Worker](https://www.youtube.com/watch?v=oDIYl3G613E)

---

## Suggested build order

1. **Connect ID** (unblocks everything else)
2. **Double Ratchet E2E** (your core security story)
3. **Disappearing messages** + **Encrypted local storage** (cheap wins, same sprint)
4. **Safety numbers** (small, high credibility)
5. **WebRTC calls** (visible, demo-friendly)
6. **Group Sender Keys**
7. **Sealed sender**
8. **Silent push**
9. **Offline mesh** (save for last — hardest, and the one you want fresh in memory for interviews)