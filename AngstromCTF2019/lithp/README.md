# Lithp

This was a fairly simple problem from Angstrom CTF 2019, a high school CTF similar to PicoCTF. I found it to be a helpful review of some basic Lisp, as I am a bit of a Lisp newbie (see, however, _Structure and Interpretation of Computer Programs_) for good practice with Scheme, a Lisp-based language). I thought I would stretch my Lisp muscles a bit with this problem.

### Problem Description

This is basically a reverse-engineering problem. [Here](./lithp.lisp) is the source code:

```common-lisp
;LITHP

(defparameter *encrypted* '(8930 15006 8930 10302 11772 13806 13340 11556 12432 13340 10712 10100 11556 12432 9312 10712 10100 10100 8930 10920 8930 5256 9312 9702 8930 10712 15500 9312))
(defparameter *flag* '(redacted))
(defparameter *reorder* '(19 4 14 3 10 17 24 22 8 2 5 11 7 26 0 25 18 6 21 23 9 13 16 1 12 15 27 20))

(defun enc (plain)
    (setf uwuth (multh plain))
    (setf uwuth (owo uwuth))
    (setf out nil)
    (dotimes (ind (length plain) out)
        (setq out (append out (list (/ (nth ind uwuth) -1))))))

(defun multh (plain)
    (cond
        ((null plain) nil)
        (t (cons (multiply (- 1 (car plain)) (car plain)) (multh (cdr plain))))))

(defun owo (inpth)
    (setf out nil)
    (do ((redth *reorder* (cdr redth)))
        ((null redth) out)
        (setq out (append out (list (nth (car redth) inpth))))))

(defun multiply (x y)
    (cond
        ((equal y 0) 0)
        (t (+ (multiply x (- y 1)) x))))

;flag was encrypted with (enc *flag*) to give *encrypted*
```
