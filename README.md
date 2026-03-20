# woltlab-login

Common Lisp library for authenticating users against a [WoltLab Community Framework](https://www.woltlab.com/) MySQL database.

## Dependencies

- [ironclad](https://github.com/sharplispers/ironclad) — bcrypt password hashing
- [cl-mysql](https://github.com/hackinghat/cl-mysql) — MySQL database access
- [babel](https://github.com/cl-babel/babel) — UTF-8 string encoding
- [cffi](https://github.com/cffi/cffi) — foreign function interface (for MySQL client library)

Install via Quicklisp or ensure these systems are available to ASDF.

## Setup

```lisp
(ql:quickload :woltlab-login)
```

On macOS with Homebrew, the library automatically adds `/opt/homebrew/opt/mysql-client/lib/` to the CFFI search path.

## API

### authenticate-user

```lisp
(authenticate-user username-or-email password
                   &key host (port 3306) database user db-password)
  => plist or nil
```

Authenticates a user by username or email address. Connects to the database, performs authentication, and disconnects. Returns a plist on success:

```lisp
(woltlab-login:authenticate-user "hans@example.com" "secret"
                                 :host "127.0.0.1"
                                 :database "forum"
                                 :user "dbuser"
                                 :db-password "dbpass")
;; =>
(:user-id 4731
 :username "hans"
 :email "hans@example.com"
 :groups ((:group-id 1 :group-name "Jeder")
          (:group-id 3 :group-name "Registrierte Benutzer")
          (:group-id 4 :group-name "Administratoren")))
```

Returns `NIL` on authentication failure (unknown user or wrong password).

### \*log-stream\*, \*log-level\*

Logging configuration. `*log-stream*` defaults to `*error-output*`. `*log-level*` defaults to `:info` and accepts `:debug`, `:info`, `:warn`, or `:error`.

Authentication attempts are logged at `:info` (success) and `:warn` (failure) levels.

## Password Hash Formats

WoltLab uses several password storage formats across versions. This library supports all three:

| Format | Algorithm | WoltLab Version |
|--------|-----------|-----------------|
| `Bcrypt:$2y$...` | Single bcrypt | Current (WCF 3.x) |
| `wcf1:$2a$...` | Double bcrypt | Legacy migration |
| `$2a$...` (bare) | Double bcrypt | Old legacy |

Double bcrypt means `bcrypt(bcrypt(password, salt), salt)`.

## Database

The library queries tables with the `wcf3_` prefix:

- `wcf3_user` — user accounts
- `wcf3_user_to_group` — group membership
- `wcf3_user_group` — group definitions
- `wcf3_language_item` — internationalized strings (for group name resolution)

## Security

- User input is escaped via `cl-mysql:escape-string` before interpolation into SQL
- Integer parameters use format directive `~D` which rejects non-numeric input
- Null bytes in input are rejected before query execution (MySQL silently truncates at null bytes)

## Testing

```lisp
(asdf:test-system :woltlab-login)
```

All tests are unit tests and require no database connection. The test suite covers bcrypt encoding, hash parsing/normalization, password verification with known hashes, logging, and SQL injection safety with 25+ adversarial payloads.

## License

MIT
