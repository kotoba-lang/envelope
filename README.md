# envelope

**One object, one content key, many wrapped copies of it.**

The encryption envelope under [kotobase.net](https://kotobase.net)'s Drive and
Mail (ADR-2607263000 D3–D5, in `com-junkawasaki/root`). An object is encrypted
once, under a random 256-bit content key. That key is never stored — only
copies of it wrapped to each recipient's X25519 public key. **Sharing re-wraps
the key; it never re-encrypts the object.**

```clojure
(require '[envelope.seal :as seal] '[envelope.model :as m])

(-> (seal/seal-object "drv:abc" (map utf8 ["chunk 0" "chunk 1"])
                      [{:id "did:key:z6Mk…" :pub alice-x25519-pub}])
    (.then (fn [{:keys [envelope chunks]}]
             ;; `chunks` are ciphertext; `envelope` is safe to store on a
             ;; server that must not be able to read the object.
             (seal/share-with envelope (seal/entry-for envelope "did:key:z6Mk…")
                              alice-priv {:id "did:key:z6Mb…" :pub bob-pub}))))
```

## Two halves, split at the crypto boundary

| ns | runtime | role |
|---|---|---|
| `envelope.model` | portable `.cljc` | the shape and every decision that needs no crypto: nonce derivation, AAD, recipients, revoke, link grants |
| `envelope.seal` | ClojureScript, `Promise`-returning | the bytes: AES-256-GCM, X25519 + HKDF-SHA256 |

`seal` is `.cljs` rather than `.cljc` because Web Crypto has no synchronous
API — the same reason `kotoba-lang/org-signal` keeps sibling JVM and CLJS
ratchets instead of one reader-conditional file. It runs where the object
actually is: a Cloudflare Worker and a browser.

X25519 and HKDF come from **`kotoba-lang/org-signal`** (audited
`@noble/curves`; Web Crypto HMAC). This repo does not reimplement them — a
second X25519 in this workspace would be a second one to get wrong.

`envelope.kem` adds the post-quantum half (`@noble/post-quantum`'s ML-KEM-768,
FIPS 203) for the `:x25519+ml-kem-768` KEM. Its docstring records why it lives
here rather than in `org-signal` (which implements X3DH, not PQXDH), and that
consolidating the workspace's three thin ML-KEM bindings is an open
opportunity.

The split is not cosmetic: the rules that decide whether this is secure —
nonce uniqueness, what the AEAD binds, what a revoke does *not* accomplish —
all live in the pure half, so they are testable on every runtime this
workspace targets, without a crypto runtime. `chunk-nonce` and `chunk-aad`
are verified to agree byte-for-byte between the JVM and ClojureScript.

## What the construction actually promises

- **Nonces are derived, never stored.** `epoch (4 bytes BE) || chunk index
  (8 bytes BE)`. GCM's one unforgivable failure is nonce reuse under a key;
  a deterministic counter makes that a property you check by reading the
  code rather than a probability you argue about. Rewriting a chunk in place
  bumps the epoch, so the rewrite gets a nonce nothing under this key has
  used — `bump-epoch` records the old epoch per chunk so untouched chunks
  keep opening.
- **The AEAD binds position, object and length.** Chunk AAD is
  `kotoba/envelope|version|object-id|epoch|index|chunk-count`. Swapping two
  chunks, replaying an old one, moving a chunk between objects, or
  truncating the object all fail to open rather than opening as something
  plausible. Each of those is a test.
- **A wrap is bound to its object and recipient**, so a wrap harvested from
  one envelope cannot be pasted into another to forge access. Also a test.
- **Revocation is honest.** `m/revoke` returns `:requires-rotation? true`
  whenever the recipient was actually present. Deleting a wrap stops someone
  deriving the content key *again*; it does not make them forget one they
  already derived. A caller that ignores the flag has built revocation
  theatre.
- **Public links are recipients too** — a link is a keypair nobody is. The
  private half goes in the URL **fragment** (`#`), which browsers never send
  to the origin; the envelope keeps only the public half. Revoking a link
  deletes its entry, and that works precisely because the link holder only
  ever had the link key, not the content key.
- **A wrap can be post-quantum, and cannot be silently downgraded to one
  that is not.** `:x25519` wraps the content key to X25519 alone, so a wrap
  harvested today opens once a CRQC exists — and the wrap *is* the object's
  confidentiality. `:x25519+ml-kem-768` derives the wrap key by HKDF over
  **both** shared secrets, so an attacker has to break both; a hybrid is never
  weaker than the classical construction it extends. The KEM is bound into the
  wrap's AAD, so a classical wrap cannot be presented where a hybrid one was
  intended, and `unwrap-with` reads the construction off the entry rather than
  negotiating it — there is no fallback path, because a fallback is the
  downgrade. Each hybrid recipient costs 1088 bytes (the ML-KEM ciphertext).
  Tests cover a wrong X25519 half, a wrong ML-KEM half, and a substituted
  encapsulation, each of which must fail on its own.
- **Identical plaintext does not deduplicate.** The content key is fresh per
  object, so two seals of the same bytes are different ciphertext.
  ADR-2607263000 D4 chose that over convergent encryption, which would leak
  whether two users hold the same file. There is a test so the property is
  not lost by accident.

## Not in scope

- **Filename and path metadata are not encrypted** by this library. Doing so
  makes an S3-compatible surface's keys opaque, which is a product decision
  (ADR-2607263000, open questions), not a crypto one.
- **No key storage, transport or identity.** Where a recipient's private key
  lives, and how a device gets one, is `kotoba-lang/org-signal` +
  ADR-2607022330 (key backup / device link) territory.
- **No chunking policy.** `chunk-count` says how many chunks a length makes;
  actually splitting, uploading and reassembling belongs to the Drive client.

## Test

```sh
npm install
nbb --classpath "src:test:../org-signal/src" scripts/run-tests.cljs
```

39 tests / 110 assertions, all against real Web Crypto, real X25519 and
real ML-KEM-768 — no fake ciphers. The negative cases (wrong key, flipped bit, reordered chunks,
truncation, relocated chunk, pasted wrap) are the point; the round trip is
the easy part.
