(ns cljakstab.core
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
       cfr))))
