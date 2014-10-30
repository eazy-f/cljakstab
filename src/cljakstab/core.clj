(ns cljakstab.core
  (:import (org.jakstab Main Options Program AnalysisManager)
           (org.jakstab.ssl Architecture)
           (org.jakstab.loader DefaultHarness)
           (org.jakstab.analysis ControlFlowReconstruction)))

(defn init-options
  "Jakstab stores options in singleton Options class"
  [opts]
  (set! org.jakstab.Options/mainFilename (:mainFile opts))
  (org.jakstab.AnalysisManager/getInstance))

(defn security-manager-proxy []
  (proxy
      [java.lang.SecurityManager] []
    (checkPermission [perm]
      (if (not (= "setSecurityManager" (.getName ^java.security.Permission perm)))
        nil))
    (checkExit [code]
      (throw
       (java.lang.SecurityException.
        (str "catched exit with code " code))))))

(defmacro disable-system-exit [& exprs]
  `(let [old-mgr# (java.lang.System/getSecurityManager)
         new-mgr# (security-manager-proxy)]
     (try
       (do
         (java.lang.System/setSecurityManager new-mgr#)
         ~@exprs)
       (finally (java.lang.System/setSecurityManager old-mgr#)))))

(defn find-jumps
  "find unresolved jumps in specified binary"
  [binary-file]
  (init-options {:mainFile binary-file})
  (disable-system-exit
   (let [arch (org.jakstab.ssl.Architecture. (.getValue org.jakstab.Options/sslFilename))
         program (org.jakstab.Program/createProgram arch)
         file (.getAbsoluteFile (java.io.File. binary-file))]
     (.loadMainModule program file)
     (.installHarness program (org.jakstab.loader.DefaultHarness.))
     (let [cfr (org.jakstab.analysis.ControlFlowReconstruction. program)]
       (.run cfr)))))
