(ns cljakstab.core
  (:require [clojure.string :as string]
            [clojure.walk   :as walk]
            [clojure.data.json :as json]
            cljakstab.rat)
  (:import (org.jakstab Main Options Program AnalysisManager)
           (org.jakstab.ssl Architecture)
           (org.jakstab.loader DefaultHarness)
           (org.jakstab.analysis ControlFlowReconstruction
                                 ConfigurableProgramAnalysis)
           org.jakstab.analysis.AbstractState
           org.jakstab.analysis.Precision
           org.jakstab.analysis.CPAOperators
           org.jakstab.util.Pair
           java.util.LinkedList
           java.security.Permission
           java.io.File))

(def ^:private global-loaded-binary nil)

(defn init-options
  "Jakstab stores options in singleton Options class"
  [opts]
  (set! Options/mainFilename (:mainFile opts))
  (AnalysisManager/getInstance))

(defn security-manager-proxy []
  (proxy
      [SecurityManager] []
    (checkPermission [perm]
      (if (not (= "setSecurityManager" (.getName ^Permission perm)))
        nil))
    (checkExit [code]
      (throw
       (SecurityException.
        (str "catched exit with code " code))))))

(defmacro disable-system-exit [& exprs]
  `(let [old-mgr# (System/getSecurityManager)
         new-mgr# (security-manager-proxy)]
     (try
       (do
         (System/setSecurityManager new-mgr#)
         ~@exprs)
       (finally (System/setSecurityManager old-mgr#)))))

(defrecord EmptyAnalysisState []
  AbstractState
  (projectionFromConcretization [& expressions]
    nil)
  (lessOrEqual [this lattice-element]
    (.equals this lattice-element)))

(defrecord EmptyAnalysis []
  ConfigurableProgramAnalysis
  (post ^{:doc "having current state return possible successor
                states for given CFA edge"}
    [this state edge precision]
    #{state})
  (initStartState [this location]
    (EmptyAnalysisState.))
  (initPrecision [this location transformer]
    nil)
  (prec [this state precision reached]
    (Pair. state precision))
  (strengthen ^{:doc "used in composite state analysis
                      `state` is this analysis state and
                      `other-states` are states of other analysis
                      if null is returned state is not touched"}
    [this state other-states cfa-edge precision]
    nil)
  (merge ^{:doc "merge two states which share same location"}
    [this state1 state2 precision]
    (CPAOperators/mergeSep state1 state2 precision))
  (stop [this state reached precision]
    (CPAOperators/stopSep state reached precision)))

(defn load-binary
  "find unresolved jumps in specified binary"
  [binary-file]
  (init-options {:mainFile binary-file})
  (disable-system-exit
   (let [arch (Architecture. (.getValue Options/sslFilename))
         program (Program/createProgram arch)
         file (.getAbsoluteFile (File. binary-file))]
     (-> "--cpa xs" ; s - call stack analysis
         (string/split #" ")
         into-array
         Options/parseOptions)
     (.loadMainModule program file)
     (.installHarness program (DefaultHarness.))
     (let [cpas (LinkedList. [(cljakstab.rat.RATAnalysis.)])
           cfr (ControlFlowReconstruction. program cpas)]
       (.run cfr)
       (def ^:private global-loaded-binary {:cfr cfr :program program})))))

(defn- get-statement
  [program location]
  (.getStatement program (.getLabel location)))

; (vector (for [loc [from to]] (get-statement program loc)))

(defn get-cfg
  "retrieve statements CFG"
  [program]
  (let [edges (-> program
                  (.getCFG)
                  (.getEdges))]
    (for [edge (seq edges)]
      (let [from (.getSource edge)
            to   (.getTarget edge)]
        [from to]))))

(defn- edge-flatten
  [edge]
  (let [[from to] edge]
    {from [to] to []}))

(defn cfg-to-stmt-map
  [cfg]
  (transduce
   (map edge-flatten)
   (completing
    (fn
      [map vertexes]
      (reduce
       (fn [submap [name successors]]
         (update submap name into successors))
       map
       vertexes)))
   {}
   cfg))

(defn remove-right-after
  [prevs cur]
  (if
   (empty? prevs)
   (conj prevs cur)
   (let [head (first prevs)
         tail (rest prevs)
         [prev-lbl prev-succ] head]
     (into tail [[prev-lbl (remove #(= (cur 0) %1) prev-succ)] cur]))))

(defn show-jumps
  [jumps]
  (if (empty? jumps)
    ""
    (str "-> [" (string/join "," jumps) "]")))

(defn get-abstract-state
  [cfr location]
  (str
   (-> cfr
    .getReachedStates
    (.where location))))

(defn get-stmt-map
  [stmt-map program cfr]
  (->>
   stmt-map
   (into (sorted-map))
   (reduce remove-right-after (list))
   reverse
   (transduce
    (map
     (fn
       [[location jumps]]
       (let [lbl (.getLabel location)]
         {
          :label lbl
          :statement (.getStatement program lbl)
          :jumps jumps
          :abstract-state (get-abstract-state cfr location)
          })))
    (completing
     (fn
       [stmts {lbl :label :as obj}]
       (if (or (zero? (.getIndex lbl)) (empty? stmts))
         (let [address (.getAddress lbl)
               instruction (.getInstruction program address)
               instruction-str (.getInstructionString program address instruction)]
           (conj stmts [instruction-str [obj]]))
         (conj (rest stmts) (update (first stmts) 1 #(conj %1 obj))))))
    (list))
    reverse))

(defn export-abstract-state
  [state]
  (str state))

(defn export-statement
  [statement]
  (into
   {}
   (map
    (fn [[name value]]
      (let [export-value (case name
                           (:label :statement) (str value)
                           (:jumps) (map str value)
                           (:abstract-state) (export-abstract-state value))]
        [name export-value]))
    statement)))

(defn export-asm-instruction
  [[asm-instruction al-stmts]]
  {:instruction asm-instruction
   :statements (map export-statement al-stmts)})

(defn export-stmt-map
  [stmts]
  (->> stmts
       (map export-asm-instruction)
       json/write-str))

(defn show-stmt-map
  [stmts]
  (map
   (fn [[location obj]]
     (println location)
     (println
      (string/join
       " "
       [
        (str (:label obj))
        (show-jumps (:jumps obj))
        (str (:abstract-state obj))])))
   stmts))
;          )))

(defn with-loaded
  [fun & args]
  (if global-loaded-binary
    (apply fun global-loaded-binary args)
    :code-not-loaded))

(defn get-code
  ([] (with-loaded get-code))
  ([loaded]
    (let [{program :program cfr :cfr} loaded]
      (-> program
          get-cfg
          cfg-to-stmt-map
          (get-stmt-map program cfr)))))

(defn list-code
  [& args]
  (show-stmt-map (apply get-code args)))

(defn show-state
  ([state-num] (with-loaded show-state state-num))
  ([loaded state-num]))

(defmacro show-symbols
  [& forms]
  `(show-symbols-fn '~forms))

(defn get-symbols-map
  [loaded]
  {1 666})

(defn show-symbols-fn
  ([forms] (with-loaded show-symbols-fn forms))
  ([loaded forms]
     (let [symbols (get-symbols-map loaded)]
       (walk/walk
        #(if (symbol? %1)
           (get symbols %1 %1)
           %1)
        identity
        forms))))
