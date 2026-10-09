;;;; env.lisp — points ASDF at deps/ and this directory, with fasls kept in deps/.fasl/.
(require :asdf)
(let ((root (uiop:getcwd)))
  (asdf:initialize-source-registry
   `(:source-registry (:tree ,(merge-pathnames "deps/" root)) (:directory ,root) :ignore-inherited-configuration))
  (asdf:initialize-output-translations
   `(:output-translations (t (,(merge-pathnames "deps/.fasl/" root) :implementation :**/ :*.*.*))
                          :ignore-inherited-configuration)))
