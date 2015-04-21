(ns cljakstab.core
  (:require [clojure.string :as string])
  (:import (org.jakstab Main Options Program AnalysisManager)
           (org.jakstab.ssl Architecture)
           (org.jakstab.loader DefaultHarness)
           (org.jakstab.analysis ControlFlowReconstruction)
           java.security.Permission
           java.io.File))

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

(defn find-jumps
  "find unresolved jumps in specified binary"
  [binary-file]
  (init-options {:mainFile binary-file})
  (disable-system-exit
   (let [arch (Architecture. (.getValue Options/sslFilename))
         program (Program/createProgram arch)
         file (.getAbsoluteFile (File. binary-file))]
     (.loadMainModule program file)
     (.installHarness program (DefaultHarness.))
     (let [cfr (ControlFlowReconstruction. program)]
       (.run cfr)
       {:cfr cfr :program program}))))

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
  (let [[from to] edge
        from_lbl  (.getLabel from)
        to_lbl    (.getLabel to)]
    {from_lbl [to_lbl] to_lbl []}))

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
   (let [[head & tail] prevs
         [prev-lbl prev-succ] head]
     (into [cur [prev-lbl (remove #(= (cur 0) %1) prev-succ)]] tail))))

(defn show-jumps
  [jumps]
  (if (empty? jumps)
    ""
    (str ": [" (string/join "," jumps) "]")))

(defn show-stmt-map
  [stmt-map program]
  (->>
   stmt-map
   (into (sorted-map))
   (reduce remove-right-after [])
   reverse
   (map
    (fn [[lbl jumps]]
      (println lbl (.getStatement program lbl) (show-jumps jumps))))
   dorun)
  nil)

(defn show-program
  [binary-file]
  (let [program (-> binary-file
                    find-jumps
                    :program)]
    (-> program
        get-cfg
        cfg-to-stmt-map
        (show-stmt-map program))))
