(ns cljakstab.core
  (:import (org.jakstab Main Options Program)
           (org.jakstab.ssl Architecture)
           (org.jakstab.loader DefaultHarness)
           (org.jakstab.analysis ControlFlowReconstruction)))

(defn foo
  "I don't do a whole lot."
  [x]
  (println x "Hello, World!"))

(defn init-options
  "Jakstab stores options in singleton Options class"
  [opts]
  (set! org.jakstab.Options/mainFilename (:mainFile opts)))


(defn find-jumps
  "find unresolved jumps in specified binary"
  [binary-file]
  (init-options {:mainFile binary-file})
  (let [arch (org.jakstab.ssl.Architecture. (.getValue org.jakstab.Options/sslFilename))
        program (org.jakstab.Program/createProgram arch)
        file (.getAbsoluteFile (java.io.File. binary-file))]
    (.loadMainModule program file)
    (.installHarness program (org.jakstab.loader.DefaultHarness.))
    (try
      (let [cfr (org.jakstab.analysis.ControlFlowReconstruction. program)]
        (.run cfr)))))


