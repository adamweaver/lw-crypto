(defpackage :base64
  (:use :cl)
  (:export "DECODE-BASE-64" "ENCODE-BASE-64"))

(defpackage :sha256
  (:use :cl)
  (:export "ENCODE-SHA256"))

(defpackage :md5
  (:use :cl)
  (:export "CRAM-MD5" "MD5-DIGEST-HEX" "MD5-HMAC-HEX"))
