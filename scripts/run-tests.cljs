;; nbb test runner (ADR-2607173000: nbb is the script host; no bb).
;;
;;   npm install                       # @noble/curves, via org-signal
;;   nbb --classpath "src:test:../org-signal/src" scripts/run-tests.cljs
;;
;; cljs.test does not set a process exit code on its own, so a failing
;; suite would otherwise exit 0 and pass CI.
(ns run-tests
  (:require [cljs.test :as t]
            [envelope.model-test]
            [envelope.projection-test]
            [envelope.seal-test]))

(defmethod t/report [::t/default :end-run-tests] [m]
  (when-not (t/successful? m)
    (js/process.exit 1)))

(t/run-tests 'envelope.model-test 'envelope.projection-test 'envelope.seal-test)
