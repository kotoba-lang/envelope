(ns envelope.kem-test
  "Real ML-KEM-768 and real X25519 — no fakes.

  The round trip is the easy part. What this has to show is that the hybrid
  is actually hybrid: that breaking either half alone breaks it, and that a
  classical wrap cannot stand in for a post-quantum one."
  (:require [cljs.test :refer [deftest is testing async]]
            [envelope.model :as m]
            [envelope.kem :as kem]
            [envelope.seal :as seal]
            [kotoba.signal.x25519 :as x25519]))

(defn- utf8 [s] (.encode (js/TextEncoder.) s))
(defn- from-utf8 [u8] (.decode (js/TextDecoder.) u8))
(defn- bytes= [^js a ^js b]
  (and (= (.-length a) (.-length b))
       (every? true? (map #(= (aget a %) (aget b %)) (range (.-length a))))))

(defn- hybrid-recipient []
  (let [x (x25519/generate-keypair)
        pq (kem/generate-keypair)]
    {:id "did:key:zTestHybrid"
     :pub (:pub x) :priv (:priv x)
     :pq-pub (:pub pq) :pq-priv (:priv pq)}))

(defn- env-for [kem]
  (assoc (m/envelope "drv:pq-test" {:chunks 1}) :envelope/kem kem))

;; ── the sizes are the ones FIPS 203 specifies ────────────────────────────

(deftest mlkem768-sizes-are-fips-203
  (let [{:keys [pub]} (kem/generate-keypair)]
    (is (= kem/public-bytes (.-length pub)))
    (is (= 1184 (.-length pub)) "ML-KEM-768 public key")))

;; ── round trip ───────────────────────────────────────────────────────────

(deftest hybrid-encapsulate-decapsulate-agree
  (async done
    (let [r (hybrid-recipient)]
      (-> (kem/encapsulate {:pub (:pub r) :pq-pub (:pq-pub r)})
          (.then (fn [{:keys [wrap-key ephemeral-pub pq-ct]}]
                   (is (= kem/wrap-key-bytes (.-length wrap-key)))
                   (is (= kem/ciphertext-bytes (.-length pq-ct))
                       "ML-KEM-768 ciphertext is 1088 B — the per-recipient price")
                   (-> (kem/decapsulate {:priv (:priv r) :pq-priv (:pq-priv r)}
                                        {:ephemeral-pub ephemeral-pub
                                         :pq-ct pq-ct
                                         :recipient-pub (:pub r)})
                       (.then (fn [wk2]
                                (is (bytes= wrap-key wk2)
                                    "both sides derive the same wrap key")
                                (done))))))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest hybrid-wrap-round-trips-a-content-key
  (async done
    (let [r (hybrid-recipient)
          env (env-for m/hybrid-kem)
          ck (.getRandomValues js/crypto (js/Uint8Array. 32))]
      (-> (seal/wrap-for-hybrid env r ck)
          (.then (fn [entry]
                   (is (= m/hybrid-kem (:recipient/kem entry)))
                   (is (some? (:recipient/pq-ct entry)))
                   (-> (seal/unwrap-with env entry (:priv r) (:pq-priv r))
                       (.then (fn [ck2]
                                (is (bytes= ck ck2))
                                (done))))))
          (.catch (fn [e] (is false (str e)) (done)))))))

;; ── it is genuinely hybrid: either half alone is not enough ──────────────

(deftest wrong-classical-half-fails
  (async done
    (let [r (hybrid-recipient)
          other (x25519/generate-keypair)
          env (env-for m/hybrid-kem)
          ck (.getRandomValues js/crypto (js/Uint8Array. 32))]
      (-> (seal/wrap-for-hybrid env r ck)
          (.then (fn [entry]
                   ;; correct ML-KEM key, wrong X25519 key
                   (-> (seal/unwrap-with env entry (:priv other) (:pq-priv r))
                       (.then (fn [_] (is false "must not open with a wrong X25519 half") (done))
                              (fn [_] (is true "rejected") (done))))))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest wrong-post-quantum-half-fails
  (async done
    (let [r (hybrid-recipient)
          other (kem/generate-keypair)
          env (env-for m/hybrid-kem)
          ck (.getRandomValues js/crypto (js/Uint8Array. 32))]
      (-> (seal/wrap-for-hybrid env r ck)
          (.then (fn [entry]
                   ;; correct X25519 key, wrong ML-KEM key
                   (-> (seal/unwrap-with env entry (:priv r) (:priv other))
                       (.then (fn [_] (is false "must not open with a wrong ML-KEM half") (done))
                              (fn [_] (is true "rejected") (done))))))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest substituted-encapsulation-fails
  (async done
    (let [r (hybrid-recipient)
          env (env-for m/hybrid-kem)
          ck (.getRandomValues js/crypto (js/Uint8Array. 32))]
      (-> (js/Promise.all
           #js [(seal/wrap-for-hybrid env r ck)
                (seal/wrap-for-hybrid env r ck)])
          (.then (fn [[a b]]
                   ;; graft the second wrap's ML-KEM ciphertext onto the first
                   (let [frankenstein (assoc a :recipient/pq-ct (:recipient/pq-ct b))]
                     (-> (seal/unwrap-with env frankenstein (:priv r) (:pq-priv r))
                         (.then (fn [_] (is false "a substituted encapsulation must not open") (done))
                                (fn [_] (is true "rejected — the transcript binds the ciphertext") (done)))))))
          (.catch (fn [e] (is false (str e)) (done)))))))

;; ── downgrade resistance ─────────────────────────────────────────────────

(deftest hybrid-and-classical-aad-differ
  (testing "so a classical wrap cannot be presented where a hybrid one is expected"
    (let [env (m/envelope "drv:abc" {:chunks 1})]
      (is (not= (m/wrap-aad env "did:key:zA" :x25519)
                (m/wrap-aad env "did:key:zA" m/hybrid-kem))))))

(deftest classical-aad-is-frozen
  (testing "every wrap already written must keep opening — the classical AAD
            must be byte-identical to what it was before the hybrid existed"
    (let [env (m/envelope "drv:abc" {:chunks 1})]
      (is (= "kotoba/envelope/wrap|1|drv:abc|did:key:zA"
             (m/wrap-aad env "did:key:zA" :x25519))))))

(deftest a-hybrid-entry-refuses-to-open-without-the-pq-key
  (async done
    (let [r (hybrid-recipient)
          env (env-for m/hybrid-kem)
          ck (.getRandomValues js/crypto (js/Uint8Array. 32))]
      (-> (seal/wrap-for-hybrid env r ck)
          (.then (fn [entry]
                   ;; no silent fallback to the classical path
                   (is (thrown? js/Error (seal/unwrap-with env entry (:priv r))))
                   (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

;; ── the classical path is untouched ──────────────────────────────────────

(deftest classical-wrap-still-round-trips
  (async done
    (let [{:keys [priv pub]} (x25519/generate-keypair)
          env (env-for :x25519)
          ck (.getRandomValues js/crypto (js/Uint8Array. 32))]
      (-> (seal/wrap-for env {:id "did:key:zClassic" :pub pub} ck)
          (.then (fn [entry]
                   (is (nil? (:recipient/kem entry)) "unchanged shape")
                   (-> (seal/unwrap-with env entry priv)
                       (.then (fn [ck2] (is (bytes= ck ck2)) (done))))))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest both-kems-are-supported-and-validate
  (is (m/valid? (assoc (m/envelope "drv:a" {:chunks 1}) :envelope/kem :x25519)))
  (is (m/valid? (assoc (m/envelope "drv:a" {:chunks 1}) :envelope/kem m/hybrid-kem)))
  (is (not (m/valid? (assoc (m/envelope "drv:a" {:chunks 1}) :envelope/kem :rsa))))
  (is (m/hybrid? (assoc (m/envelope "drv:a" {:chunks 1}) :envelope/kem m/hybrid-kem)))
  (is (not (m/hybrid? (m/envelope "drv:a" {:chunks 1})))))
