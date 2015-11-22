(ns cljakstab.rat
  (:require [clojure.string :as string])
  (:import (org.jakstab.analysis ConfigurableProgramAnalysis
                                 AbstractState
                                 Precision
                                 CPAOperators)
           org.jakstab.analysis.explicit.BasedNumberValuation
           org.jakstab.util.Pair
           (org.jakstab.rtl.expressions RTLMemoryLocation
                                        ExpressionFactory)))

; RAT - Return Address Tracking

(defrecord RATAnalysisState [^clojure.lang.PersistentHashSet return-address]
  AbstractState
  (projectionFromConcretization [& expressions]
    nil)
  (lessOrEqual [this lattice-element]
    (.equals this lattice-element))
  (isBot [this]
    (empty? return-address))
  (toString [this]
    (str 
     "RAT: ["
     (string/join ", " (map str return-address))
     "]")))

(defn put-return-address
  [rat-state address]
  (RATAnalysisState. (conj (.return-address rat-state) address)))

(defn get-return-address-value
  [bat-state]
  (let [bitwidth 32
        ebp (ExpressionFactory/createVariable "ebp" bitwidth)
        word (ExpressionFactory/createNumber 4 bitwidth)
        ret (ExpressionFactory/createMinus ebp word)
        return-address (ExpressionFactory/createMemoryLocation ret bitwidth)]
    (.abstractEval bat-state return-address)))

(defrecord RATAnalysis []
  ConfigurableProgramAnalysis
  (post [this state edge precision]
    #{state})
  (initStartState [this location]
    (RATAnalysisState. #{}))
  (initPrecision [this location transformer]
    nil)
  (prec [this state precision reached]
    (Pair. state precision))
  (strengthen [this state other-states cfa-edge precision]
    (reduce
     (fn [rat-state bat-state]
       (put-return-address rat-state (get-return-address-value bat-state)))
     state
     (take 1 (filter #(instance? BasedNumberValuation %1) other-states))))
  (merge [this state1 state2 precision]
    (CPAOperators/mergeSep state1 state2 precision))
  (stop [this state reached precision]
    (CPAOperators/stopSep state reached precision)))

