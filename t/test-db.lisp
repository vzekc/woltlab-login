;;;; -*- Mode: Lisp; Coding: utf-8 -*-
;;;; Test database utilities for woltlab-login
;;;;
;;;; Provides functions to create and manage a local MySQL test database
;;;; with the WoltLab table schema needed for authentication testing.
;;;;
;;;; Quick start:
;;;;   (woltlab-login/test-db:with-test-database (db)
;;;;     (create-user db "alice" "alice@example.com" "secret123")
;;;;     (create-user db "bob" "bob@example.com" "hunter2")
;;;;     (let ((group-id (create-group db "Admins")))
;;;;       (add-user-to-group db 1 group-id))
;;;;     ;; Now test authenticate-user against this database
;;;;     (woltlab-login:authenticate-user "alice" "secret123"
;;;;       :host "127.0.0.1" :database (db-name db)
;;;;       :user "root" :password ""))

(defpackage #:woltlab-login/test-db
  (:use #:cl)
  (:export #:test-db
           #:db-name
           #:db-connection
           #:create-test-db
           #:destroy-test-db
           #:with-test-database
           #:create-user
           #:update-user
           #:delete-user
           #:change-password
           #:find-user
           #:create-group
           #:rename-group
           #:delete-group
           #:add-user-to-group
           #:remove-user-from-group
           #:list-users
           #:list-groups
           #:hash-password))

(in-package #:woltlab-login/test-db)

;;; Configuration

(defparameter *default-host* "127.0.0.1")
(defparameter *default-port* 3306)
(defparameter *default-user* "root")
(defparameter *default-password* "")
(defparameter *default-bcrypt-cost* 4)  ; low cost for fast tests

;;; Test database handle

(defstruct test-db
  name
  connection
  host
  (port 3306)
  user
  password)

;;; Password hashing (reuses woltlab-login internals)

(defun hash-password (password &key (cost *default-bcrypt-cost*) (format :bcrypt))
  "Hash PASSWORD for storage in the test database.
FORMAT is :bcrypt (default, modern Bcrypt:$2y$...), :wcf1 (legacy double-hash),
or :legacy (bare double-hash $2a$...)."
  (let* ((salt (ironclad:random-data 16))
         (password-bytes (babel:string-to-octets password :encoding :utf-8))
         (hash (woltlab-login::bcrypt-hash-password password-bytes cost salt)))
    (ecase format
      (:bcrypt
       ;; Modern format: Bcrypt:$2y$...
       (concatenate 'string "Bcrypt:"
                    (concatenate 'string "$2y$" (subseq hash 4))))
      (:wcf1
       ;; Legacy wcf1: double bcrypt
       (let ((double-hash (woltlab-login::bcrypt-hash-password
                           (babel:string-to-octets hash :encoding :utf-8)
                           cost salt)))
         (concatenate 'string "wcf1:" double-hash)))
      (:legacy
       ;; Bare double bcrypt
       (woltlab-login::bcrypt-hash-password
        (babel:string-to-octets hash :encoding :utf-8)
        cost salt)))))

;;; SQL helpers

(defun exec (db sql &rest args)
  "Execute a SQL statement. ARGS are interpolated with FORMAT."
  (let ((query (if args (apply #'format nil sql args) sql)))
    (cl-mysql:query query :database (test-db-connection db))))

(defun query-rows (db sql &rest args)
  "Execute a SQL query and return all rows."
  (let ((result (apply #'exec db sql args)))
    (caar result)))

(defun query-one (db sql &rest args)
  "Execute a SQL query and return the first row."
  (car (apply #'query-rows db sql args)))

;;; Database lifecycle

(defun make-unique-db-name ()
  "Generate a unique database name for testing."
  (format nil "woltlab_test_~A_~A"
          (get-universal-time)
          (random 10000)))

(defun create-tables (db)
  "Create the WoltLab tables needed for authentication."
  (exec db "CREATE TABLE wcf3_user (
    userID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")

  (exec db "CREATE TABLE wcf3_user_group (
    groupID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    groupName VARCHAR(255) NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")

  (exec db "CREATE TABLE wcf3_user_to_group (
    userID INT NOT NULL,
    groupID INT NOT NULL,
    PRIMARY KEY (userID, groupID),
    FOREIGN KEY (userID) REFERENCES wcf3_user(userID) ON DELETE CASCADE,
    FOREIGN KEY (groupID) REFERENCES wcf3_user_group(groupID) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")

  (exec db "CREATE TABLE wcf3_language_item (
    languageItemID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    languageID INT NOT NULL DEFAULT 1,
    languageItem VARCHAR(255) NOT NULL,
    languageItemValue VARCHAR(255) NOT NULL,
    UNIQUE KEY (languageItem, languageID)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"))

(defun create-test-db (&key (host *default-host*) (port *default-port*)
                         (user *default-user*) (password *default-password*)
                         name)
  "Create a fresh test database with WoltLab tables.
Returns a TEST-DB handle. Call DESTROY-TEST-DB when done."
  (let* ((db-name (or name (make-unique-db-name)))
         (conn (cl-mysql:connect :host host :port port
                                 :user user :password password)))
    (cl-mysql:query (format nil "CREATE DATABASE IF NOT EXISTS `~A` CHARACTER SET utf8mb4" db-name)
                    :database conn)
    (cl-mysql:query (format nil "USE `~A`" db-name) :database conn)
    (let ((db (make-test-db :name db-name
                            :connection conn
                            :host host
                            :port port
                            :user user
                            :password password)))
      (create-tables db)
      db)))

(defun destroy-test-db (db)
  "Drop the test database and close the connection."
  (when db
    (let ((conn (test-db-connection db)))
      (when conn
        (ignore-errors
          (cl-mysql:query (format nil "DROP DATABASE IF EXISTS `~A`" (test-db-name db))
                          :database conn))
        (ignore-errors
          (cl-mysql:disconnect conn))))))

(defmacro with-test-database ((db &rest make-args) &body body)
  "Execute BODY with DB bound to a fresh test database.
The database is destroyed when BODY exits (normally or via error).
MAKE-ARGS are passed to MAKE-TEST-DB.

Example:
  (with-test-database (db)
    (create-user db \"alice\" \"alice@example.com\" \"password\")
    (woltlab-login:authenticate-user \"alice\" \"password\"
      :host \"127.0.0.1\" :database (db-name db)
      :user \"root\" :password \"\"))"
  `(let ((,db (create-test-db ,@make-args)))
     (unwind-protect (progn ,@body)
       (destroy-test-db ,db))))

;;; Accessor for connection parameters (useful for authenticate-user calls)

(defun db-name (db)
  "Return the database name, for passing to authenticate-user."
  (test-db-name db))

(defun db-connection (db)
  "Return the raw MySQL connection."
  (test-db-connection db))

;;; User management

(defun create-user (db username email password &key (hash-format :bcrypt)
                                                 (bcrypt-cost *default-bcrypt-cost*))
  "Create a user and return the new userID.
PASSWORD is hashed automatically. HASH-FORMAT can be :bcrypt, :wcf1, or :legacy."
  (let ((hashed (hash-password password :cost bcrypt-cost :format hash-format))
        (escaped-username (cl-mysql:escape-string username
                                                  :database (test-db-connection db)))
        (escaped-email (cl-mysql:escape-string email
                                               :database (test-db-connection db)))
        )
    (exec db "INSERT INTO wcf3_user (username, email, password) VALUES ('~A', '~A', '~A')"
          escaped-username escaped-email
          (cl-mysql:escape-string hashed :database (test-db-connection db)))
    ;; Get the auto-generated ID
    (let ((row (query-one db "SELECT LAST_INSERT_ID()")))
      (first row))))

(defun update-user (db user-id &key username email)
  "Update a user's username and/or email."
  (let ((sets nil)
        (conn (test-db-connection db)))
    (when username
      (push (format nil "username = '~A'"
                    (cl-mysql:escape-string username :database conn))
            sets))
    (when email
      (push (format nil "email = '~A'"
                    (cl-mysql:escape-string email :database conn))
            sets))
    (when sets
      (exec db "UPDATE wcf3_user SET ~{~A~^, ~} WHERE userID = ~D"
            sets user-id))))

(defun delete-user (db user-id)
  "Delete a user by ID. Also removes group memberships (via CASCADE)."
  (exec db "DELETE FROM wcf3_user WHERE userID = ~D" user-id))

(defun change-password (db user-id new-password &key (hash-format :bcrypt)
                                                  (bcrypt-cost *default-bcrypt-cost*))
  "Change a user's password."
  (let ((hashed (hash-password new-password :cost bcrypt-cost :format hash-format)))
    (exec db "UPDATE wcf3_user SET password = '~A' WHERE userID = ~D"
          (cl-mysql:escape-string hashed :database (test-db-connection db))
          user-id)))

(defun find-user (db &key username email user-id)
  "Find a user. Returns (userID username email password) or NIL."
  (let ((conn (test-db-connection db)))
    (cond
      (user-id
       (query-one db "SELECT userID, username, email, password FROM wcf3_user WHERE userID = ~D"
                  user-id))
      (username
       (query-one db "SELECT userID, username, email, password FROM wcf3_user WHERE username = '~A'"
                  (cl-mysql:escape-string username :database conn)))
      (email
       (query-one db "SELECT userID, username, email, password FROM wcf3_user WHERE email = '~A'"
                  (cl-mysql:escape-string email :database conn))))))

(defun list-users (db)
  "List all users. Returns list of (userID username email)."
  (query-rows db "SELECT userID, username, email FROM wcf3_user ORDER BY userID"))

;;; Group management

(defun create-group (db group-name &key language-value)
  "Create a group and return its groupID.
If LANGUAGE-VALUE is provided, the group-name is stored as a language key
(like WoltLab does) and a language_item entry maps it to LANGUAGE-VALUE."
  (let* ((conn (test-db-connection db))
         (escaped-name (cl-mysql:escape-string group-name :database conn)))
    (exec db "INSERT INTO wcf3_user_group (groupName) VALUES ('~A')" escaped-name)
    (let ((group-id (first (query-one db "SELECT LAST_INSERT_ID()"))))
      (when language-value
        (exec db "INSERT INTO wcf3_language_item (languageID, languageItem, languageItemValue) ~
                  VALUES (1, '~A', '~A')"
              escaped-name
              (cl-mysql:escape-string language-value :database conn)))
      group-id)))

(defun rename-group (db group-id new-name &key language-value)
  "Rename a group. Optionally update or set its language translation."
  (let ((conn (test-db-connection db)))
    ;; Get old name for language_item update
    (let ((old-row (query-one db "SELECT groupName FROM wcf3_user_group WHERE groupID = ~D" group-id)))
      (when old-row
        (let ((old-name (first old-row))
              (escaped-new (cl-mysql:escape-string new-name :database conn)))
          (exec db "UPDATE wcf3_user_group SET groupName = '~A' WHERE groupID = ~D"
                escaped-new group-id)
          ;; Update language item if it existed
          (when old-name
            (exec db "UPDATE wcf3_language_item SET languageItem = '~A' WHERE languageItem = '~A'"
                  escaped-new
                  (cl-mysql:escape-string old-name :database conn)))
          (when language-value
            (exec db "INSERT INTO wcf3_language_item (languageID, languageItem, languageItemValue) ~
                      VALUES (1, '~A', '~A') ~
                      ON DUPLICATE KEY UPDATE languageItemValue = '~A'"
                  escaped-new
                  (cl-mysql:escape-string language-value :database conn)
                  (cl-mysql:escape-string language-value :database conn))))))))

(defun delete-group (db group-id)
  "Delete a group by ID. Also removes user-to-group memberships (via CASCADE)."
  ;; Clean up language items first
  (let ((row (query-one db "SELECT groupName FROM wcf3_user_group WHERE groupID = ~D" group-id)))
    (when row
      (exec db "DELETE FROM wcf3_language_item WHERE languageItem = '~A'"
            (cl-mysql:escape-string (first row) :database (test-db-connection db)))))
  (exec db "DELETE FROM wcf3_user_group WHERE groupID = ~D" group-id))

(defun list-groups (db)
  "List all groups with resolved names.
Returns list of (groupID groupName resolvedName-or-NIL)."
  (query-rows db "SELECT g.groupID, g.groupName, li.languageItemValue ~
                  FROM wcf3_user_group g ~
                  LEFT JOIN wcf3_language_item li ~
                    ON li.languageItem = g.groupName AND li.languageID = 1 ~
                  ORDER BY g.groupID"))

;;; Group membership

(defun add-user-to-group (db user-id group-id)
  "Add a user to a group."
  (exec db "INSERT IGNORE INTO wcf3_user_to_group (userID, groupID) VALUES (~D, ~D)"
        user-id group-id))

(defun remove-user-from-group (db user-id group-id)
  "Remove a user from a group."
  (exec db "DELETE FROM wcf3_user_to_group WHERE userID = ~D AND groupID = ~D"
        user-id group-id))
