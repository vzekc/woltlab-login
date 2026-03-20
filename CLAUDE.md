# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Common Lisp library for authenticating users against a WoltLab Community Forum MySQL database. Single-file implementation in `src/woltlab-login.lisp`.

## Commands

```bash
# Run tests
sbcl --noinform --non-interactive \
  --eval "(pushnew *default-pathname-defaults* asdf:*central-registry* :test (quote equal))" \
  --eval "(asdf:test-system :woltlab-login)"

# Or from a running Lisp
(asdf:test-system :woltlab-login)
```

Tests are pure unit tests requiring no database connection.

## Architecture

All code lives in `src/woltlab-login.lisp` with a single package `woltlab-login`.

**Password verification** supports three WoltLab hash formats:
- `Bcrypt:$2y$...` — newer WoltLab, single bcrypt
- `wcf1:$2a$...` — legacy, double bcrypt (bcrypt of bcrypt)
- Bare `$2a$...` — old legacy, double bcrypt

The `$2y$` variant is normalized to `$2a$` before verification (functionally identical). Ironclad's bcrypt KDF returns 24 bytes but standard bcrypt uses only 23 — output must be truncated.

**Database tables** use the `wcf3_` prefix (not `wcf1_`). Group names stored as language keys (e.g. `wcf.acp.group.group1`) are resolved via `LEFT JOIN` on `wcf3_language_item`.

**SQL safety**: cl-mysql has no prepared statement support. String inputs are escaped with `cl-mysql:escape-string`. Integer parameters use `~D` format directive. Null bytes in input are rejected before query execution.

## MCP / Swank

The `.mcp.json` configures a Lisp MCP server connecting to Swank on port 4005, enabling REPL interaction for live debugging.
