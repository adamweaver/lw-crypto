(in-package :cl-user)

(define-lw-system crypto ()
  (:file "package")
  (:file "base64" :depends-on "package")
  (:file "sha256" :depends-on "package")
  (:file "md5" :depends-on "base64"))

