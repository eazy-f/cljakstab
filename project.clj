(defproject cljakstab "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.7.0"]
;                 [jakstab "0.1.4"]
                 [antlr "0.1"]
                 [com.google.guava/guava "18.0"]
                 [org.clojure/data.json "0.2.6"]]
  :repositories {"local" "file:java-lib"}
  :resource-paths ["../jakstab-git/lib/jakstab.jar"]
  :jvm-opts ["-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"])
