(in-package :sha256)

(defun constrain-32 (integer)
  (logand integer 4294967295))

(defun rotate-right-32 (integer count)
  (logior (constrain-32 (ash integer (- count))) (constrain-32 (ash integer (- 32 count)))))

(defun rotate-left-32 (integer count)
  (logior (constrain-32 (ash integer count)) (constrain-32 (ash integer (- 32 count)))))

(defun big-endian-32 (integer)
  #+little-endian
  (logior (ash (logand integer #x000000ff) 24)
          (ash (logand integer #x0000ff00) 8)
          (ash (logand integer #x00ff0000) -8)
          (ash (logand integer #xff000000) -24))
  #-little-endian
  integer)

(deftype positive-fixnum ()
  `(integer 0 ,most-positive-fixnum))

(deftype small-fixnum ()
  `(integer 0 64))

(defconstant +sha256-h+ #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19))
(defvar %sha256-h0% nil)
(defvar %sha256-h1% nil)
(defvar %sha256-h2% nil)
(defvar %sha256-h3% nil)
(defvar %sha256-h4% nil)
(defvar %sha256-h5% nil)
(defvar %sha256-h6% nil)
(defvar %sha256-h7% nil)

(defun %sha256-init ()
  (setf %sha256-h0% (svref +sha256-h+ 0)
        %sha256-h1% (svref +sha256-h+ 1)
        %sha256-h2% (svref +sha256-h+ 2)
        %sha256-h3% (svref +sha256-h+ 3)
        %sha256-h4% (svref +sha256-h+ 4)
        %sha256-h5% (svref +sha256-h+ 5)
        %sha256-h6% (svref +sha256-h+ 6)
        %sha256-h7% (svref +sha256-h+ 7)))

(defconstant +sha256-k+ #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
                          #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
                          #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
                          #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
                          #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
                          #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
                          #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
                          #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))

(defun %sha256-preprocess-message (string &aux (pre-length (rem (1+ (length string)) 64)))
  (let ((message (make-array (length string) :element-type '(fixnum 0 255) :initial-contents (map 'list #'char-code string) :adjustable t :fill-pointer t)))
    (vector-push-extend 128 message)
    (loop repeat (if (< pre-length 56) (- 56 pre-length) (+ 56 (- 64 pre-length))) do (vector-push-extend 0 message))
    (loop with length = (* 8 (length string))
          for pos from -56 upto 0 by 8 do
            (vector-push-extend (logand 255 (ash length pos)) message))
    message))

(defun %sha256-chunkify-message (message)
  (loop with length = (length message)
        for i from 0 below length by 64 collect
                                        (subseq message i (+ i 64))))

(defun %sha256-make-message-schedule-array (chunk)
  (let ((message-schedule-array (make-array 64 :element-type '(integer 0 4294967295) :initial-element 0)))
    (loop for i below 64 by 4
          for j from 0
          for a = (aref chunk i)
          for b = (aref chunk (1+ i))
          for c = (aref chunk (+ i 2))
          for d = (aref chunk (+ i 3)) do
            (setf (aref message-schedule-array j) (logior (ash a 24) (ash b 16) (ash c 8) d)))
    message-schedule-array))

(defun %sha256-main-loop (msa)
  (loop for i from 16 to 63
        for w15 = (aref msa (- i 15))
        for w2 = (aref msa (- i 2))
        for s0 = (logxor (rotate-right-32 w15 7) (rotate-right-32 w15 18) (ash w15 -3))
        for s1 = (logxor (rotate-right-32 w2 17) (rotate-right-32 w2 19) (ash w2 -10)) do
          (setf (aref msa i) (constrain-32 (+ (aref msa (- i 16)) s0 (aref msa (- i 7)) s1))))

  (let ((a %sha256-h0%) (b %sha256-h1%) (c %sha256-h2%) (d %sha256-h3%) (e %sha256-h4%) (f %sha256-h5%) (g %sha256-h6%) (h %sha256-h7%))
    (loop for i to 63
          for s1 = (logxor (rotate-right-32 e 6) (rotate-right-32 e 11) (rotate-right-32 e 25))
          for ch = (logxor (logand e f) (logand (lognot e) g))
          for temp1 = (constrain-32 (+ h s1 ch (svref +sha256-k+ i) (aref msa i)))
          for s0 = (logxor (rotate-right-32 a 2) (rotate-right-32 a 13) (rotate-right-32 a 22))
          for maj = (logxor (logand a b) (logand a c) (logand b c))
          for temp2 = (constrain-32 (+ s0 maj)) do
            (setf h g
                  g f
                  f e
                  e (constrain-32 (+ d temp1))
                  d c
                  c b
                  b a
                  a (constrain-32 (+ temp1 temp2))))

    (setf %sha256-h0% (constrain-32 (+ %sha256-h0% a))
          %sha256-h1% (constrain-32 (+ %sha256-h1% b))
          %sha256-h2% (constrain-32 (+ %sha256-h2% c))
          %sha256-h3% (constrain-32 (+ %sha256-h3% d))
          %sha256-h4% (constrain-32 (+ %sha256-h4% e))
          %sha256-h5% (constrain-32 (+ %sha256-h5% f))
          %sha256-h6% (constrain-32 (+ %sha256-h6% g))
          %sha256-h7% (constrain-32 (+ %sha256-h7% h)))))

(defun %sha256-produce-digest ()
  (format nil "~8,'0X~8,'0X~8,'0X~8,'0X~8,'0X~8,'0X~8,'0X~8,'0X" %sha256-h0% %sha256-h1% %sha256-h2% %sha256-h3% %sha256-h4% %sha256-h5% %sha256-h6% %sha256-h7%))

(defun encode-sha256 (string &optional (rounds 1))
  (let (%sha256-h0% %sha256-h1% %sha256-h2% %sha256-h3% %sha256-h4% %sha256-h5% %sha256-h6% %sha256-h7%)
    (%sha256-init)
    (let* ((message (%sha256-preprocess-message string))
           (chunks (%sha256-chunkify-message message)))
      (loop repeat rounds do
        (loop for chunk in chunks do
          (%sha256-main-loop (%sha256-make-message-schedule-array chunk)))))
    (%sha256-produce-digest)))
