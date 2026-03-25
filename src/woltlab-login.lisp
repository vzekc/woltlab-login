;;;; -*- Mode: Lisp; Coding: utf-8 -*-

(defpackage #:woltlab-login
  (:use #:cl)
  (:export #:authenticate-user
           #:lookup-user-email
           #:lookup-user
           #:*log-stream*
           #:*log-level*
           #:*log-function*))

(in-package #:woltlab-login)

;;; Logging

(defvar *log-stream* *error-output*
  "Stream for log output. Used by the default log function.")

(defvar *log-level* :info
  "Minimum log level to output. One of :debug, :info, :warn, :error.")

(defvar *log-function* nil
  "When non-nil, a function of (level fmt &rest args) called instead of
the built-in logger. This allows the host application to integrate
woltlab-login logging into its own logging facility.")

(defparameter *log-level-priority*
  '(:debug 0 :info 1 :warn 2 :error 3))

(defun log-message (level fmt &rest args)
  "Write a log message. When *log-function* is set, delegates to it.
Otherwise writes a timestamped message to *log-stream*."
  (cond (*log-function*
         (apply *log-function* level fmt args))
        (t
         (when (>= (getf *log-level-priority* level 0)
                   (getf *log-level-priority* *log-level* 0))
           (multiple-value-bind (sec min hour day month year)
               (decode-universal-time (get-universal-time))
             (format *log-stream* "~4,'0D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D [~A] ~?~%"
                     year month day hour min sec
                     (string-upcase (symbol-name level))
                     fmt args)
             (force-output *log-stream*))))))

;;; Ensure cl-mysql can find libmysqlclient on macOS (Homebrew keg-only)
;;; and fall back to libmariadb on Linux (Debian/Ubuntu)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((brew-lib (merge-pathnames "lib/" "/opt/homebrew/opt/mysql-client/")))
    (when (probe-file brew-lib)
      (pushnew brew-lib cffi:*foreign-library-directories* :test #'equal)))
  (cffi:define-foreign-library libmysqlclient
    (:unix (:or "libmysqlclient_r" "libmysqlclient" "libmariadb"))
    (t (:default "libmysqlclient"))))

;;; Bcrypt modified base64 encoding/decoding
;;;
;;; Bcrypt uses a non-standard base64 alphabet:
;;;   ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789

(defparameter *bcrypt-base64-chars*
  "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

(defparameter *bcrypt-base64-decode-table*
  (let ((table (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for char across *bcrypt-base64-chars*
          for i from 0
          do (setf (aref table (char-code char)) i))
    table))

(defun bcrypt-base64-decode (encoded)
  "Decode a bcrypt modified base64 string to a byte vector."
  (let* ((len (length encoded))
         (full-groups (floor len 4))
         (remainder (mod len 4))
         (n-bytes (+ (* full-groups 3)
                     (case remainder (0 0) (2 1) (3 2) (t 0))))
         (result (make-array n-bytes :element-type '(unsigned-byte 8)))
         (table *bcrypt-base64-decode-table*)
         (ri 0))
    (flet ((val (i) (aref table (char-code (char encoded i)))))
      (dotimes (g full-groups)
        (let* ((si (* g 4))
               (c0 (val si)) (c1 (val (+ si 1)))
               (c2 (val (+ si 2))) (c3 (val (+ si 3))))
          (setf (aref result ri) (logior (ash c0 2) (ash c1 -4)))
          (setf (aref result (+ ri 1)) (logand #xff (logior (ash c1 4) (ash c2 -2))))
          (setf (aref result (+ ri 2)) (logand #xff (logior (ash c2 6) c3)))
          (incf ri 3)))
      (when (>= remainder 2)
        (let* ((si (* full-groups 4))
               (c0 (val si)) (c1 (val (+ si 1))))
          (setf (aref result ri) (logior (ash c0 2) (ash c1 -4)))
          (incf ri)
          (when (>= remainder 3)
            (let ((c2 (val (+ si 2))))
              (setf (aref result ri) (logand #xff (logior (ash c1 4) (ash c2 -2)))))))))
    result))

(defun bcrypt-base64-encode (bytes n-chars)
  "Encode a byte vector to bcrypt modified base64, producing exactly N-CHARS characters."
  (let ((chars *bcrypt-base64-chars*)
        (result (make-string n-chars))
        (bi 0)
        (ri 0)
        (len (length bytes)))
    (flet ((byte-or-0 (i) (if (< i len) (aref bytes i) 0)))
      (loop while (< ri n-chars) do
        (let ((b0 (byte-or-0 bi))
              (b1 (byte-or-0 (+ bi 1)))
              (b2 (byte-or-0 (+ bi 2))))
          (when (< ri n-chars)
            (setf (char result ri) (char chars (ash b0 -2)))
            (incf ri))
          (when (< ri n-chars)
            (setf (char result ri) (char chars (logior (ash (logand b0 #x03) 4)
                                                       (ash b1 -4))))
            (incf ri))
          (when (< ri n-chars)
            (setf (char result ri) (char chars (logior (ash (logand b1 #x0f) 2)
                                                       (ash b2 -6))))
            (incf ri))
          (when (< ri n-chars)
            (setf (char result ri) (char chars (logand b2 #x3f)))
            (incf ri))
          (incf bi 3))))
    result))

;;; Bcrypt hash computation using ironclad's bcrypt KDF

(defun parse-bcrypt-hash (hash-string)
  "Parse a bcrypt hash string ($2a$CC$<22-salt><31-hash>) into cost and raw salt bytes."
  (unless (and (>= (length hash-string) 29)
               (char= (char hash-string 0) #\$)
               (char= (char hash-string 3) #\$)
               (char= (char hash-string 6) #\$))
    (error "Invalid bcrypt hash format: ~A" hash-string))
  (let ((cost (parse-integer hash-string :start 4 :end 6))
        (salt-encoded (subseq hash-string 7 29)))
    (values cost (bcrypt-base64-decode salt-encoded))))

(defun bcrypt-hash-password (password-bytes cost salt)
  "Compute a bcrypt hash and return the full hash string ($2a$CC$<salt><hash>).
PASSWORD-BYTES is a byte vector, COST is the cost factor (e.g. 8),
SALT is a 16-byte raw salt vector."
  (let* ((kdf (ironclad:make-kdf :bcrypt))
         (iteration-count (expt 2 cost))
         (raw-hash (subseq (ironclad:derive-key kdf password-bytes salt iteration-count 24) 0 23))
         (salt-encoded (bcrypt-base64-encode salt 22))
         (hash-encoded (bcrypt-base64-encode raw-hash 31)))
    (format nil "$2a$~2,'0D$~A~A" cost salt-encoded hash-encoded)))

(defun parse-stored-hash (stored-hash)
  "Parse WoltLab's stored password hash. Returns (values algorithm bcrypt-hash).
Algorithm is :bcrypt for 'Bcrypt:' prefix (single bcrypt),
:wcf1 for 'wcf1:' prefix (double bcrypt), or :legacy for bare $2a$ hashes (double bcrypt)."
  (let ((colon-pos (position #\: stored-hash :end (min 10 (length stored-hash)))))
    (if colon-pos
        (let ((prefix (subseq stored-hash 0 colon-pos))
              (hash (subseq stored-hash (1+ colon-pos))))
          (values (cond ((string-equal prefix "Bcrypt") :bcrypt)
                        ((string-equal prefix "wcf1") :wcf1)
                        (t nil))
                  hash))
        (values :legacy stored-hash))))

(defun normalize-bcrypt-hash (hash)
  "Normalize $2y$ to $2a$ for verification purposes."
  (if (and (>= (length hash) 4) (string= (subseq hash 0 4) "$2y$"))
      (concatenate 'string "$2a$" (subseq hash 4))
      hash))

(defun verify-woltlab-password (password stored-hash)
  "Verify a password against a WoltLab stored hash.
Supports three formats: Bcrypt: (single bcrypt), wcf1: (double bcrypt),
and bare $2a$ hashes (legacy double bcrypt)."
  (handler-case
      (multiple-value-bind (algorithm hash) (parse-stored-hash stored-hash)
        (unless algorithm
          (return-from verify-woltlab-password nil))
        (let ((hash (normalize-bcrypt-hash hash)))
          (unless (and (>= (length hash) 7)
                       (string= (subseq hash 0 4) "$2a$"))
            (return-from verify-woltlab-password nil))
          (multiple-value-bind (cost salt) (parse-bcrypt-hash hash)
            (let* ((password-bytes (babel:string-to-octets password :encoding :utf-8))
                   (computed (bcrypt-hash-password password-bytes cost salt)))
              ;; wcf1 and legacy formats use double bcrypt: bcrypt(bcrypt(password))
              (when (member algorithm '(:wcf1 :legacy))
                (setf computed (bcrypt-hash-password
                                (babel:string-to-octets computed :encoding :utf-8)
                                cost salt)))
              (string= computed hash)))))
    (error () nil)))

;;; Database connection

(defun connect (&key host (port 3306) database user password)
  "Connect to the WoltLab MySQL database."
  (cl-mysql:connect :host host
                    :port port
                    :database database
                    :user user
                    :password password))

(defun disconnect (connection)
  "Disconnect from the database."
  (when connection
    (cl-mysql:disconnect connection)))

;;; User authentication

(defun query-first-row (query-string connection)
  "Execute a SQL query and return the first data row as a list, or NIL."
  (let* ((result (cl-mysql:query query-string :database connection))
         (rows (caar result)))
    ;; cl-mysql returns: ((rows-list field-list) ...)
    ;; (caar result) = rows-list: list of row value lists, or NIL if no matches
    ;; (cadar result) = field-list: column metadata (always present)
    (when rows
      (car rows))))

(defun query-all-rows (query-string connection)
  "Execute a SQL query and return all data rows as a list of lists."
  (let ((result (cl-mysql:query query-string :database connection)))
    (caar result)))

(defun query-user (username-or-email connection)
  "Query wcf3_user by username or email. Returns (userID username email password) or NIL."
  (when (find #\Nul username-or-email)
    (log-message :warn "Rejecting input containing null byte")
    (return-from query-user nil))
  (let ((escaped (cl-mysql:escape-string username-or-email :database connection)))
    (or (query-first-row
         (format nil "SELECT userID, username, email, password FROM wcf3_user WHERE username = '~A'" escaped)
         connection)
        (query-first-row
         (format nil "SELECT userID, username, email, password FROM wcf3_user WHERE email = '~A'" escaped)
         connection))))

(defun authenticate-user (username-or-email password
                          &key host (port 3306) database user db-password)
  "Authenticate a user against the WoltLab database.
Connects to the database, performs authentication, and disconnects.
Returns a plist (:user-id ... :username ... :email ... :groups ...) on success, NIL on failure."
  (let ((connection (connect :host host :port port :database database
                             :user user :password db-password)))
    (unwind-protect
         (let ((row (query-user username-or-email connection)))
           (unless row
             (log-message :warn "Authentication failed: user not found: ~A" username-or-email)
             (return-from authenticate-user nil))
           (destructuring-bind (user-id username email stored-hash) row
             (unless (verify-woltlab-password password stored-hash)
               (log-message :warn "Authentication failed: invalid password for user ~A" username)
               (return-from authenticate-user nil))
             (log-message :info "Authentication successful for user ~A (ID ~D)" username user-id)
             (list :user-id user-id
                   :username username
                   :email email
                   :groups (user-groups user-id connection))))
      (disconnect connection))))

(defun lookup-user-email (username-or-email
                          &key host (port 3306) database user db-password)
  "Look up a user's email by username without authentication.
Connects to the database, queries, and disconnects.
Returns the email string on success, NIL if not found."
  (let ((connection (connect :host host :port port :database database
                             :user user :password db-password)))
    (unwind-protect
         (let ((row (query-user username-or-email connection)))
           (when row
             (destructuring-bind (user-id username email stored-hash) row
               (declare (ignore user-id stored-hash))
               (log-message :info "Email lookup for ~A: found" username)
               email)))
      (disconnect connection))))

(defun lookup-user (username-or-email
                    &key host (port 3306) database user db-password)
  "Look up user data by username without authentication.
Connects to the database, queries, and disconnects.
Returns a plist (:user-id ... :username ... :email ... :groups ...) or NIL."
  (let ((connection (connect :host host :port port :database database
                             :user user :password db-password)))
    (unwind-protect
         (let ((row (query-user username-or-email connection)))
           (when row
             (destructuring-bind (user-id username email stored-hash) row
               (declare (ignore stored-hash))
               (log-message :info "User lookup for ~A (ID ~D)" username user-id)
               (list :user-id user-id
                     :username username
                     :email email
                     :groups (user-groups user-id connection)))))
      (disconnect connection))))

;;; Group memberships

(defun user-groups (user-id connection)
  "Fetch group memberships for a user.
Returns a list of plists ((:group-id ... :group-name ...) ...).
Resolves WoltLab language keys (e.g. wcf.acp.group.group1) to their translated names."
  (mapcar (lambda (row)
            (list :group-id (first row)
                  :group-name (or (third row) (second row))))
          (query-all-rows
           (format nil "SELECT g.groupID, g.groupName, li.languageItemValue ~
                        FROM wcf3_user_to_group ug ~
                        JOIN wcf3_user_group g ON ug.groupID = g.groupID ~
                        LEFT JOIN wcf3_language_item li ~
                          ON li.languageItem = g.groupName AND li.languageID = 1 ~
                        WHERE ug.userID = ~D" user-id)
           connection)))
