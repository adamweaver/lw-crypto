(in-package :zlib)

(defstruct huffman
  length code)

(defun decompress (vec)
  (let ((compression-method (ldb (byte 4 0) (aref vec 0)))
        (compression-info (ldb (byte 4 4) (aref vec 0)))
        (flag-fcheck (ldb (byte 4 0) (aref vec 1)))
        (flag-fdict (ldb (byte 1 5) (aref vec 1)))
        (flag-flevel (ldb (byte 2 6) (aref vec 1)))
        (byte 1)
        (bit 7)
        (out (make-array 16384 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))

    (labels ((read-bit (count))

             (make-huffman-decode-tree (lengths)
               (let* ((max (reduce #'max lengths))
                      (bl-count (make-array (1+ max) :initial-element 0))
                      (next-code (make-array (1+ max) :initial-element 0)))
                 (loop for l across lengths do (incf (aref bl-count l)))
                 (loop for bits from 1 upto max
                       for code = 0 then (ash (+ code (aref bl-count (1- bits))) 1)
                       do (setf (aref next-code bits) code))
                 (loop for len across lengths
                       unless (zerop len)
                         collect (make-huffman :length len :code (aref next-code len))
                         and do (incf (aref next-code len)))))

             (read-noncompressed ()
               (unless (= bit 7)
                 (setf bit 7 byte (1+ byte)))
               (let ((len (+ (ash (aref vec byte) 8) (aref vec (1+ byte)))))
                 (copy-to-output (+ byte 2) (+ byte 2 len))
                 (incf byte (+  2 len))))

             (read-fixed ())

             (read-dynamic ())

             (copy-to-output (start len)
               (unless (< (+ (fill-pointer out) len) (array-total-size out))
                 (setf out (adjust-array out (* (ceiling len 16384) 16384)))
                 (replace out vec :start1 (fill-pointer out) :start2 start :end2 (+ start len))
                 (incf (fill-pointer out) len))))
      
      (loop for bfinal = (read-bit 1)
            for btype = (read-bit 2)
            do (case btype
                 (0 (read-noncompressed))
                 (1 (read-fixed))
                 (2 (read-dynamic))
                 (t (error "Unknown BTYPE ~A" btype)))
            when bfinal do (loop-finish)))))


