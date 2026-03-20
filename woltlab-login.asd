;;;; -*- Mode: Lisp; Coding: utf-8 -*-

(asdf:defsystem #:woltlab-login
  :description "Authenticate users against WoltLab MySQL database"
  :author "Hans Hubner"
  :license "MIT"
  :depends-on (#:ironclad
               #:cl-mysql
               #:babel
               #:cffi)
  :serial t
  :pathname "src"
  :components ((:file "woltlab-login"))
  :in-order-to ((test-op (test-op #:woltlab-login/tests))))

(asdf:defsystem #:woltlab-login/tests
  :depends-on (#:woltlab-login)
  :pathname "t"
  :components ((:file "tests"))
  :perform (test-op (o c)
             (symbol-call :woltlab-login/tests :run-tests)))
