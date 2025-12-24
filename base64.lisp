(in-package :base64)

(defun decode-base-64 (string)
  "Convert STRING into an (unsigned-byte 8)"
  ;; (declare (optimize (speed 3) (safety 0) (debug 0)) (type string string))
  (let* ((strlen* (length string))
         (strlen (- strlen* (if (char= (char string (- strlen* 2)) #\=) 2 (if (char= (char string (1- strlen*)) #\=) 1 0))))
         (regular-len (* 4 (the positive-fixnum (floor strlen 4))))
         (output-len (+ (the positive-fixnum (* 3 (the positive-fixnum (/ regular-len 4))))
                        (the positive-fixnum (if (> strlen regular-len) (the positive-fixnum (- strlen regular-len 1)) 0))))
         (vector (make-array output-len :element-type '(unsigned-byte 8))))
    (declare (type positive-fixnum strlen* strlen regular-len output-len))
    (decode-base-64-from-normal-string-into-vector string vector 0 strlen regular-len)
    vector))

(defun decode-base-64-from-normal-string-into-vector (string vector start strlen regular-len)
  (flet ((value (c)
           (declare (inline value) (ftype (function (character) (unsigned-byte 8)) value))
           (let ((val (char-code c)))
             (cond ((> val 96) (- val 71))
                   ((> val 64) (- val 65))
                   ((> val 47) (+ val 4))
                   ((= val 43) 62)
                   (t 63)))))

    ;; Loop below our regular len (unpadded sets of 4)
    (loop for i of-type positive-fixnum below regular-len by 4
          for o of-type positive-fixnum from start by 3
          for b0 of-type (unsigned-byte 8) = (value (char string i))
          for b1 of-type (unsigned-byte 8) = (value (char string (the positive-fixnum (1+ i))))
          for b2 of-type (unsigned-byte 8) = (value (char string (the positive-fixnum (+ i 2))))
          for b3 of-type (unsigned-byte 8) = (value (char string (the positive-fixnum (+ i 3))))
          do (setf (aref vector o)       (logior (ash b0 2) (ldb (byte 2 4) b1))
                   (aref vector (1+ o))  (logior (ash (ldb (byte 4 0) b1) 4) (ldb (byte 4 2) b2))
                   (aref vector (+ 2 o)) (logior (ash (ldb (byte 2 0) b2) 6) b3)))

    ;; If our strlen /= regular-len then we need to look at the last 2 or 3 characters
    (unless (= strlen regular-len)
      (let ((o (* 3 (the positive-fixnum (/ regular-len 4))))
            (i0 (value (char string regular-len)))
            (i1 (value (char string (the positive-fixnum (1+ regular-len))))))
        (declare (type positive-fixnum o) (type (unsigned-byte 8) i0 i1))
        (setf (aref vector o) (logior (ash (ldb (byte 6 0) i0) 2) (ldb (byte 2 4) i1)))
        (when (> (the positive-fixnum (- strlen regular-len)) 2)
          (let ((i2 (value (char string (the positive-fixnum (+ 2 regular-len))))))
            (declare (type (unsigned-byte 8) i2))
            (setf (aref vector (1+ o)) (logior (ash (ldb (byte 4 0) i1) 4) (ldb (byte 4 2) i2)))))))))

(defconstant +base64-table+
  #.(make-array 64 :element-type 'base-char :initial-contents "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"))

(defun encode-base-64 (vector)
  "Convert VECTOR into a string in MIME base64 (final characters #\+ and #\/)"
  (if (stringp vector)
      (encode-base-64 (map 'vector #'char-code vector))
      (let* ((veclen (length vector))
             (strlen (* 4 (the positive-fixnum (ceiling veclen 3))))
             (extras (mod veclen 3))
             (string (make-string strlen :element-type 'base-char)))
        (declare (type positive-fixnum veclen strlen extras))
        (loop for i of-type positive-fixnum below (the positive-fixnum (- veclen extras)) by 3
              for o of-type positive-fixnum by 4
              for i0 of-type (unsigned-byte 8) = (aref vector i)
              for i1 of-type (unsigned-byte 8) = (aref vector (the positive-fixnum (1+ i)))
              for i2 of-type (unsigned-byte 8) = (aref vector (the positive-fixnum (+ i 2)))
              do (setf (lw:sbchar string o) (aref +base64-table+ (ldb (byte 6 2) i0))
                       (lw:sbchar string (the positive-fixnum (1+ o))) (aref +base64-table+ (dpb (ldb (byte 2 0) i0) (byte 2 4) (ldb (byte 4 4) i1)))
                       (lw:sbchar string (the positive-fixnum (+ 2 o))) (aref +base64-table+ (dpb (ldb (byte 4 0) i1) (byte 4 2) (ldb (byte 2 6) i2)))
                       (lw:sbchar string (the positive-fixnum (+ 3 o))) (aref +base64-table+ (ldb (byte 6 0) i2))))
        (when (plusp extras)
          (let ((i0 (aref vector (- veclen extras)))
                (i1 (if (= extras 2) (aref vector (1- veclen)) 0)))
            (declare (type (unsigned-byte 8) i0 i1))
            (setf (lw:sbchar string (- strlen 4)) (aref +base64-table+ (ldb (byte 6 2) i0))
                  (lw:sbchar string (- strlen 3)) (aref +base64-table+ (dpb (ldb (byte 4 0) i0) (byte 2 4) (ldb (byte 4 4) i1)))
                  (lw:sbchar string (- strlen 2)) (if (= extras 2) (aref +base64-table+ (dpb (ldb (byte 4 0) i1) (byte 4 2) 0)) #\=)
                  (lw:sbchar string (1- strlen)) #\=)))
        string)))

