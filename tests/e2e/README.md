# Console e2e harness

`console.mjs` is a local, real-browser pass over the served console. It boots
its own stack, drives headless Chrome over the DevTools protocol, and asserts
what the source-level console tests cannot see: rendering, theming,
localisation and a clean JS console in a real browser. It is not wired into CI.

## What it does

1. Boots a throwaway HTTP mail sink and a private `openwarp-server` on loopback
   with a temp SQLite database and `OPENWARP_EMAIL_WEBHOOK` pointed at the sink.
2. Registers a user through `register-v2`, reads the verification link out of
   the sink, verifies, and logs in with the `challenge`/`login-v2` HMAC proof.
3. Launches headless Chrome (`--headless=new --remote-debugging-port=0` with a
   temp profile), installs the login's `ow_session` cookie into the browser
   (the console's emergency-status polls authenticate by cookie and send no
   Authorization header), injects the session token into the console's
   in-memory `T`, and calls the console's own `enterApp()`.
4. Walks the first four nav pages and screenshots each, then checks:
   - theme: `cycleTheme()` writes `ow_theme` to localStorage; both the stored
     preference and the applied palette survive a reload;
   - language: the first non-English, non-`system` entry of `.langsel`
     translates the auth title through `owSetLang()` and survives a reload;
   - exceptions: no JavaScript exceptions on the page at any point in the pass.

PASS/FAIL lines go to stderr. The exit code is nonzero when any step fails.
Screenshots land in `.agents/state/e2e-matrix/screens/` (gitignored); each run
replaces the previous set, so captures from a failed run never linger.

On a fresh account two captures document intended behaviour rather than
defects: the Integrations nav bounces to Apps with an "Open an app first"
toast because that view is app-scoped (`needAppEnv`), and the post-reload
language capture shows the resumed shell because the `ow_session` cookie
re-authenticates the reload into the app.

## Run it

    cargo build -p openwarp-server
    node tests/e2e/console.mjs

Requires Google Chrome at the default application path and Node 22+ (global
`WebSocket`). The harness kills its own server and Chrome on exit, including
through the failure path. After a hard kill, clean leftovers with
`pkill -f console.mjs` and check for stray `openwarp-server` or headless
Chrome processes before rerunning.
