(ns envelope.seal-test
  "Real crypto, no fakes: every assertion here runs Web Crypto AES-GCM and
  @noble/curves X25519. The negative cases matter more than the positive
  one — an envelope that opens is easy, an envelope that refuses to open
  the wrong thing is the product."
  (:require [cljs.test :refer [deftest is testing async]]
            [envelope.model :as m]
            [envelope.seal :as seal]
            [kotoba.signal.x25519 :as x25519]))

(defn- utf8 [s] (.encode (js/TextEncoder.) s))
(defn- from-utf8 [u8] (.decode (js/TextDecoder.) u8))

(defn- recipient []
  (let [{:keys [priv pub]} (x25519/generate-keypair)]
    {:priv priv :pub pub :id (str "did:key:test-" (seal/b64url pub))}))

(defn- fails
  "Promise that resolves true when `p` rejects, false when it resolves.
  Written out rather than assumed: a test that awaits a rejection and
  forgets to assert it passes silently."
  [p]
  (-> p (.then (fn [_] false)) (.catch (fn [_] true))))

(deftest an-object-round-trips-through-one-recipient
  (async done
    (let [alice (recipient)
          plaintext ["chunk zero" "chunk one" "chunk two"]]
      (-> (seal/seal-object "obj:1" (map utf8 plaintext) [{:id (:id alice) :pub (:pub alice)}])
          (.then (fn [{:keys [envelope chunks]}]
                   (is (m/valid? envelope))
                   (is (= 3 (count chunks)))
                   (is (= [(:id alice)] (m/recipient-ids envelope)))
                   (testing "the content key is nowhere in the envelope"
                     (is (not (contains? envelope :envelope/content-key))))
                   (seal/open-object envelope (seal/entry-for envelope (:id alice))
                                     (:priv alice) chunks)))
          (.then (fn [opened]
                   (is (= plaintext (mapv from-utf8 opened)))
                   (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest a-stranger-cannot-open-it
  (async done
    (let [alice (recipient)
          mallory (recipient)]
      (-> (seal/seal-object "obj:2" [(utf8 "secret")] [{:id (:id alice) :pub (:pub alice)}])
          (.then (fn [{:keys [envelope chunks]}]
                   (fails (seal/open-object envelope
                                            (seal/entry-for envelope (:id alice))
                                            (:priv mallory) chunks))))
          (.then (fn [rejected?] (is (true? rejected?)) (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest tampering-with-a-byte-is-detected
  (async done
    (let [alice (recipient)]
      (-> (seal/seal-object "obj:3" [(utf8 "secret")] [{:id (:id alice) :pub (:pub alice)}])
          (.then (fn [{:keys [envelope chunks]}]
                   (let [ct (js/Uint8Array.from (first chunks))]
                     (aset ct 0 (bit-xor (aget ct 0) 1))
                     (fails (seal/open-object envelope
                                              (seal/entry-for envelope (:id alice))
                                              (:priv alice) #js [ct])))))
          (.then (fn [rejected?] (is (true? rejected?)) (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest chunks-cannot-be-reordered
  ;; the AAD binds the index, so a valid chunk in the wrong slot is invalid
  (async done
    (let [alice (recipient)]
      (-> (seal/seal-object "obj:4" [(utf8 "zero") (utf8 "one")]
                            [{:id (:id alice) :pub (:pub alice)}])
          (.then (fn [{:keys [envelope chunks]}]
                   (fails (seal/open-object envelope
                                            (seal/entry-for envelope (:id alice))
                                            (:priv alice)
                                            [(second chunks) (first chunks)]))))
          (.then (fn [rejected?] (is (true? rejected?)) (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest an-object-cannot-be-truncated
  ;; the AAD binds the chunk COUNT, so dropping the tail changes what every
  ;; remaining chunk authenticates against
  (async done
    (let [alice (recipient)]
      (-> (seal/seal-object "obj:5" [(utf8 "a") (utf8 "b") (utf8 "c")]
                            [{:id (:id alice) :pub (:pub alice)}])
          (.then (fn [{:keys [envelope chunks]}]
                   (let [shortened (assoc envelope :envelope/chunks 2)]
                     (fails (seal/open-object shortened
                                              (seal/entry-for shortened (:id alice))
                                              (:priv alice) (take 2 chunks))))))
          (.then (fn [rejected?] (is (true? rejected?)) (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest a-chunk-cannot-be-moved-to-another-object
  (async done
    (let [alice (recipient)
          r [{:id (:id alice) :pub (:pub alice)}]]
      (-> (js/Promise.all
           #js [(seal/seal-object "obj:6a" [(utf8 "from a")] r)
                (seal/seal-object "obj:6b" [(utf8 "from b")] r)])
          (.then (fn [[a b]]
                   ;; b's envelope, a's ciphertext
                   (fails (seal/open-object (:envelope b)
                                            (seal/entry-for (:envelope b) (:id alice))
                                            (:priv alice) (:chunks a)))))
          (.then (fn [rejected?] (is (true? rejected?)) (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest a-wrap-cannot-be-pasted-into-another-envelope
  ;; wrap-aad binds the object id, so harvesting alice's wrap from one
  ;; object and pasting it into another does not grant access to that other
  (async done
    (let [alice (recipient)
          r [{:id (:id alice) :pub (:pub alice)}]]
      (-> (js/Promise.all
           #js [(seal/seal-object "obj:7a" [(utf8 "a")] r)
                (seal/seal-object "obj:7b" [(utf8 "b")] r)])
          (.then (fn [[a b]]
                   (let [stolen (seal/entry-for (:envelope a) (:id alice))
                         forged (m/put-recipient (:envelope b) stolen)]
                     (fails (seal/open-object forged (seal/entry-for forged (:id alice))
                                              (:priv alice) (:chunks b))))))
          (.then (fn [rejected?] (is (true? rejected?)) (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest sharing-re-wraps-and-never-re-encrypts
  (async done
    (let [alice (recipient)
          bob (recipient)]
      (-> (seal/seal-object "obj:8" [(utf8 "shared secret")]
                            [{:id (:id alice) :pub (:pub alice)}])
          (.then (fn [{:keys [envelope chunks]}]
                   (-> (seal/share-with envelope
                                        (seal/entry-for envelope (:id alice))
                                        (:priv alice)
                                        {:id (:id bob) :pub (:pub bob)})
                       (.then (fn [env']
                                (is (= 2 (count (:envelope/recipients env'))))
                                (testing "no chunk was touched"
                                  (is (= (m/chunk-epoch envelope 0) (m/chunk-epoch env' 0))))
                                (seal/open-object env' (seal/entry-for env' (:id bob))
                                                  (:priv bob) chunks))))))
          (.then (fn [opened]
                   (is (= "shared secret" (from-utf8 (first opened))))
                   (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest a-link-holder-opens-with-the-fragment-secret-and-loses-it-on-revoke
  (async done
    (let [alice (recipient)
          state (atom nil)]
      (-> (seal/seal-object "obj:9" [(utf8 "link me")]
                            [{:id (:id alice) :pub (:pub alice)}])
          (.then (fn [{:keys [envelope chunks]}]
                   (reset! state {:chunks chunks})
                   (seal/mint-link envelope
                                   (seal/entry-for envelope (:id alice))
                                   (:priv alice))))
          (.then (fn [{env' :envelope grant :grant}]
                   (let [entry (seal/entry-for env' (:grant/recipient-id grant))]
                     (swap! state assoc :env env' :entry entry :grant grant)
                     (is (m/link? entry))
                     (testing "the envelope carries only the public half"
                       (is (not= (:grant/secret grant) (:recipient/pub entry))))
                     (seal/open-object env' entry (:grant/secret grant) (:chunks @state)))))
          (.then (fn [opened]
                   (is (= "link me" (from-utf8 (first opened))))
                   (let [{:keys [env entry]} @state
                         revoked (:envelope (m/revoke env (:recipient/id entry)))]
                     (is (nil? (seal/entry-for revoked (:recipient/id entry)))
                         "the link's only way in is the entry that was just deleted"))
                   (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest two-seals-of-the-same-bytes-differ
  ;; content-addressing happens over the ciphertext, and the content key is
  ;; fresh per object — so identical plaintext deduplicates to nothing.
  ;; ADR-2607263000 D4 chose exactly this over convergent encryption; the
  ;; test exists so the property is not lost by accident.
  (async done
    (let [alice (recipient)
          r [{:id (:id alice) :pub (:pub alice)}]]
      (-> (js/Promise.all
           #js [(seal/seal-object "obj:10a" [(utf8 "identical bytes")] r)
                (seal/seal-object "obj:10b" [(utf8 "identical bytes")] r)])
          (.then (fn [[a b]]
                   (is (not= (seal/b64url (first (:chunks a)))
                             (seal/b64url (first (:chunks b)))))
                   (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest base64url-round-trips-and-stays-url-safe
  (let [bytes (js/Uint8Array.from #js [251 255 254 0 1 62 63])
        s (seal/b64url bytes)]
    (is (not (re-find #"[+/=]" s)) "a link secret has to survive a URL fragment")
    (is (= (vec (array-seq bytes)) (vec (array-seq (seal/unb64url s)))))))
