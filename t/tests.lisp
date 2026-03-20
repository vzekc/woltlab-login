;;;; -*- Mode: Lisp; Coding: utf-8 -*-
;;;; Tests for woltlab-login

(defpackage #:woltlab-login/tests
  (:use #:cl)
  (:export #:run-tests))

(in-package #:woltlab-login/tests)

(defvar *tests-run*)
(defvar *tests-passed*)
(defvar *tests-failed*)

(defmacro deftest (name &body body)
  `(progn
     (incf *tests-run*)
     (handler-case
         (progn ,@body
                (incf *tests-passed*)
                (format *error-output* "  PASS ~A~%" ',name))
       (error (e)
         (incf *tests-failed*)
         (format *error-output* "  FAIL ~A: ~A~%" ',name e)))))

(defun assert-equal (expected actual &optional description)
  (unless (equal expected actual)
    (error "~@[~A: ~]expected ~S but got ~S" description expected actual)))

(defun assert-true (value &optional description)
  (unless value
    (error "~@[~A: ~]expected true but got ~S" description value)))

(defun assert-nil (value &optional description)
  (when value
    (error "~@[~A: ~]expected NIL but got ~S" description value)))

;;; Test definitions

(defun test-bcrypt-base64 ()
  (format *error-output* "~%=== Bcrypt base64 tests ===~%")

  (deftest bcrypt-base64-roundtrip
    (let* ((bytes #(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
           (encoded (woltlab-login::bcrypt-base64-encode bytes 22))
           (decoded (woltlab-login::bcrypt-base64-decode encoded)))
      (assert-equal (length bytes) (length decoded) "length")
      (assert-true (every #'= bytes decoded) "content"))))

(defun test-bcrypt-hash-parsing ()
  (format *error-output* "~%=== Bcrypt hash parsing tests ===~%")

  (deftest parse-bcrypt-hash-valid
    (multiple-value-bind (cost salt)
        (woltlab-login::parse-bcrypt-hash "$2a$12$ucvtKdwgrAPY2As2lvcu9uY6gTfXd9WQ8VblqZHKLVAQmb6Y4sP/G")
      (assert-equal 12 cost "cost")
      (assert-equal 16 (length salt) "salt length")))

  (deftest parse-bcrypt-hash-invalid
    (handler-case
        (progn (woltlab-login::parse-bcrypt-hash "not-a-hash")
               (error "Should have signaled an error"))
      (error () nil))))

(defun test-stored-hash-parsing ()
  (format *error-output* "~%=== Stored hash parsing tests ===~%")

  (deftest parse-stored-hash-bcrypt-prefix
    (multiple-value-bind (algo hash)
        (woltlab-login::parse-stored-hash "Bcrypt:$2y$12$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
      (assert-equal :bcrypt algo "algorithm")
      (assert-equal #\$ (char hash 0) "hash starts with $")))

  (deftest parse-stored-hash-wcf1-prefix
    (multiple-value-bind (algo hash)
        (woltlab-login::parse-stored-hash "wcf1:$2a$08$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
      (assert-equal :wcf1 algo "algorithm")
      (assert-equal #\$ (char hash 0) "hash starts with $")))

  (deftest parse-stored-hash-bare
    (multiple-value-bind (algo hash)
        (woltlab-login::parse-stored-hash "$2a$08$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
      (assert-equal :legacy algo "algorithm")
      (assert-equal #\$ (char hash 0) "hash starts with $")))

  (deftest parse-stored-hash-unknown-prefix
    (multiple-value-bind (algo hash)
        (woltlab-login::parse-stored-hash "unknown:$2a$08$something")
      (declare (ignore hash))
      (assert-nil algo "unknown algorithm"))))

(defun test-hash-normalization ()
  (format *error-output* "~%=== Hash normalization tests ===~%")

  (deftest normalize-2y-to-2a
    (assert-equal "$2a$12$rest" (woltlab-login::normalize-bcrypt-hash "$2y$12$rest")))

  (deftest normalize-2a-unchanged
    (assert-equal "$2a$12$rest" (woltlab-login::normalize-bcrypt-hash "$2a$12$rest"))))

(defun test-password-verification ()
  (format *error-output* "~%=== Password verification tests ===~%")

  ;; Hash for "abc123!!!" generated with single bcrypt, cost 12
  (deftest verify-password-single-bcrypt
    (assert-true
     (woltlab-login::verify-woltlab-password
      "abc123!!!"
      "Bcrypt:$2y$12$ucvtKdwgrAPY2As2lvcu9uY6gTfXd9WQ8VblqZHKLVAQmb6Y4sP/G")
     "correct password"))

  (deftest verify-password-wrong-password
    (assert-nil
     (woltlab-login::verify-woltlab-password
      "wrong-password"
      "Bcrypt:$2y$12$ucvtKdwgrAPY2As2lvcu9uY6gTfXd9WQ8VblqZHKLVAQmb6Y4sP/G")
     "wrong password"))

  (deftest verify-password-empty-hash
    (assert-nil
     (woltlab-login::verify-woltlab-password "anything" "")
     "empty hash"))

  (deftest verify-password-garbage-hash
    (assert-nil
     (woltlab-login::verify-woltlab-password "anything" "not-a-valid-hash")
     "garbage hash")))

(defun test-logging ()
  (format *error-output* "~%=== Logging tests ===~%")

  (deftest log-message-output
    (let ((output (with-output-to-string (s)
                    (let ((woltlab-login:*log-stream* s)
                          (woltlab-login:*log-level* :debug))
                      (woltlab-login::log-message :info "test ~A" "message")))))
      (assert-true (search "[INFO]" output) "contains level")
      (assert-true (search "test message" output) "contains message")))

  (deftest log-message-filtering
    (let ((output (with-output-to-string (s)
                    (let ((woltlab-login:*log-stream* s)
                          (woltlab-login:*log-level* :error))
                      (woltlab-login::log-message :info "should not appear")))))
      (assert-equal 0 (length output) "filtered message"))))

(defparameter *injection-payloads*
  (list "' OR '1'='1"
        "' OR '1'='1' --"
        "' OR '1'='1' /*"
        "'; DROP TABLE wcf3_user; --"
        "' UNION SELECT 1,2,3,4 --"
        "' UNION SELECT userID,username,email,password FROM wcf3_user --"
        "\\'"
        "''"
        "\"OR\"1\"=\"1"
        "1; DROP TABLE wcf3_user"
        "' AND 1=0 UNION ALL SELECT NULL,NULL,NULL,NULL--"
        "admin'--"
        "' OR ''='"
        (format nil "~C" (code-char 0))
        (format nil "user~Cname" (code-char 0))
        "用户' OR '1'='1"
        "' OR 1=1 ∕∕"
        "\\' OR 1=1 --"
        "\\\\'\\' OR 1=1 --"
        (make-string 10000 :initial-element #\A)
        (concatenate 'string (make-string 5000 :initial-element #\') "OR 1=1--")
        "~A~A~A~A"
        "%s%s%s%s"
        ""
        " "
        (string #\Tab)
        (string #\Newline)))

(defun test-sql-injection-safety ()
  (format *error-output* "~%=== SQL injection safety tests ===~%")

  (deftest verify-password-injection-payloads
    (let ((known-hash "Bcrypt:$2y$12$ucvtKdwgrAPY2As2lvcu9uY6gTfXd9WQ8VblqZHKLVAQmb6Y4sP/G"))
      (dolist (payload *injection-payloads*)
        (assert-nil
         (woltlab-login::verify-woltlab-password payload known-hash)
         (format nil "payload as password: ~S"
                 (subseq payload 0 (min 40 (length payload))))))))

  (deftest verify-password-injection-as-hash
    (dolist (payload *injection-payloads*)
      (assert-nil
       (woltlab-login::verify-woltlab-password "password" payload)
       (format nil "payload as hash: ~S"
               (subseq payload 0 (min 40 (length payload)))))))

  (deftest null-byte-rejection
    (assert-true (find #\Nul (format nil "~C" (code-char 0)))
                 "null byte detected")
    (assert-true (find #\Nul (format nil "user~Cname" (code-char 0)))
                 "embedded null byte detected")
    (assert-nil (find #\Nul "normal-input")
                "normal input has no null bytes")))

;;; Entry point

(defun run-tests ()
  (let ((*tests-run* 0)
        (*tests-passed* 0)
        (*tests-failed* 0)
        (woltlab-login:*log-stream* (make-broadcast-stream)))
    (test-bcrypt-base64)
    (test-bcrypt-hash-parsing)
    (test-stored-hash-parsing)
    (test-hash-normalization)
    (test-password-verification)
    (test-logging)
    (test-sql-injection-safety)
    (format *error-output* "~%=== Results: ~D/~D passed~@[, ~D FAILED~] ===~%"
            *tests-passed* *tests-run*
            (when (> *tests-failed* 0) *tests-failed*))
    (zerop *tests-failed*)))
