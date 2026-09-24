# WP Vuln Scanner

Static **and** dynamic WordPress vulnerability scanner.

```
wp_scanner.py            unified CLI (--mode static|dynamic|all)
wp_vuln_scanner.py       static analyser  : taint aware PHP/WP source review
wp_scan_rules.py         rule database    : sources, sinks, sanitizers, CWEs
wp_dynamic_common.py     shared helpers   : Target (requests session), results
wp_dynamic_recon.py      dynamic recon    : version, xmlrpc, users, secrets, headers
wp_dynamic_checks.py     dynamic exploits : RCE, SQLi, LFI, upload, XSS, redirect
wp_exploit_framework.py  dynamic CLI      : orchestration + report
wp_report.py             JSON + HTML report rendering
Dockerfile.scanner       container image for the scanner
requirements.txt         runtime dependency (requests)
```

## Why it was rewritten

The previous scripts produced mostly **noise and no signal**:

* `wp_vuln_scanner.py` grepped for "dangerous functions" line by line, so any
  `echo`/`include` was reported while real `$wpdb->query()` injection was missed,
  and it hardcoded a report URL that was no longer reachable.
* `wp_exploit_framework.py` treated `status == 200 and len(body) > 10` as proof
  of a vulnerability, which is a false positive generator: an unknown
  `admin-ajax.php` action returns HTTP 200 with a `0` body.

The new implementation replaces guesses with **taint analysis** (static) and
**hard evidence** (dynamic).

## Static analyser

Detection strategy, per PHP file:

1. the file is split into functions (brace matching, UTF-8 safe);
2. **taint tracking** – variables assigned from `$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES`,
   transitively through further assignments, become *tainted*;
3. a rule only fires when a **sink** is reachable from taint in the *same call*
   (`call_span()`), which is why `echo 'hello';` is not reported while
   `echo $msg;` is;
4. **sanitizers suppress the rule** – `esc_html`, `intval`, `$wpdb->prepare`,
   `wp_handle_upload`, `wp_safe_redirect`, `escapeshellarg`, …;
5. `wp_ajax_nopriv_*` handlers are cross referenced with the handler body: an
   unauthenticated action is reported only when a sink that *survives* the
   sanitizer check is present and no nonce/capability check exists
   (which removes the false positive on a safe `nopriv` search endpoint);
6. file level rules add hardcoded secrets.

Detected classes (with CWE mapping):

| id | category | severity | CWE |
|---|---|---|---|
| rce-command-injection | rce | critical | CWE-78 |
| rce-code-eval | rce | critical | CWE-95 |
| rce-callback-injection | rce | high | CWE-94 |
| sqli-wpdb-interpolation | sqli | critical | CWE-89 |
| sqli-raw-driver | sqli | high | CWE-89 |
| upload-unrestricted | file_upload | critical | CWE-434 |
| lfi-arbitrary-file-read | lfi | high | CWE-98 |
| xss-unescaped-output | xss | medium | CWE-79 |
| redirect-open | open_redirect | medium | CWE-601 |
| deserialization-untrusted | deserialization | high | CWE-502 |
| ssrf-user-url | ssrf | medium | CWE-918 |
| weak-password-hash | weak_hash | medium | CWE-916 |
| secret-* | hardcoded_secret | high | CWE-798 |
| unauth-ajax-action | unauth_action | high | CWE-862 |

### Usage

```bash
python wp_scanner.py --mode static --path ./wp-content/plugins --out static_report
python wp_scanner.py --mode static --path C:/wordpress/wp-content/plugins --min-severity high
python wp_vuln_scanner.py --path ./wp-content/plugins --out report
python wp_vuln_scanner.py --url https://site.tld/wp-content/plugins/   # mirror + scan
```

Output: `static_report.json` (machine readable) and `static_report.html`.

## Dynamic scanner

Each active check must produce **evidence**, never just an HTTP 200:

| check | evidence required |
|---|---|
| command-injection | unique marker echoed back by `echo`/`sleep` side channel |
| sqli | database error text, or a `SLEEP()` payload delaying the response ≥ 3.5 s |
| lfi | content of `/etc/passwd` (`root:x:0:0`) or `wp-config.php` (`DB_PASSWORD`) |
| file-upload-rce | uploaded PHP file is fetched back and **executes** its marker |
| reflected-xss | payload returned verbatim (not HTML escaped) |
| open-redirect | `Location:` header pointing to an attacker controlled host |
| deserialization | serialized object is reconstructed server side |
| xmlrpc / user-enum / sensitive files / headers | fingerprint and exposure facts |

Candidate endpoints cover a generic set of fallbacks (`/?file=`, `/?redirect=`,
`/?cmd=`, admin-ajax actions, …) so the tool stays useful against production
sites.

### Usage

```bash
python wp_scanner.py --mode dynamic --url http://localhost:8080 --out dynamic_report
python wp_exploit_framework.py --url https://site.tld --no-active --min-severity low
python wp_exploit_framework.py --url https://site.tld --only sqli --fail-on high
```

## Notes and limitations

Findings from validating against a real vulnerable WordPress instance, all
handled in the code:

* **WordPress applies `addslashes()` to request data** (`wp_magic_quotes`), so a
  literal `'` arrives as `\'` and `"` as `\"`. A naive `1' OR SLEEP(5)--`
  payload is therefore silently neutralised and the scanner would report a false
  negative. The SQLi check consequently also sends the backslash escaped form
  `1\' ...`, which `addslashes()` turns into `1\\' ...` and the string literal
  then closes again. Real vulnerable plugins mirror this by calling
  `wp_unslash()` on the input.
* **`/bin/sh` (dash) rejects `"; ;"`** as a syntax error. For a sink shaped like
  `system('id; ' . $cmd)` the classic `;echo MARKER;#` payload produces
  `id; ;echo MARKER;#` and never runs, so the RCE check tries several payload
  shapes (`; echo X`, `echo X`, `$(echo X)`) before falling back to timing.
* **Not-installed sites redirect everything.** While `is_blog_installed()` is
  false, WordPress sends the visitor to `wp-admin/install.php` for *every* path.
  That made the sensitive file recon report `/.env` as exposed, because a
  followed redirect produced HTTP 200. `check_sensitive_files` therefore no
  longer follows redirects, uses anchored signatures
  (`(?m)^[A-Z0-9_]{2,}\s*=` for `.env`, `PHP (Fatal|Warning|Notice|Parse)` for
  `debug.log`) and drops the response when it equals a random canary path
  (soft 404 guard).

* Static taint tracking is intra-procedural: taint is followed through
  assignments inside one function, not across function boundaries or object
  properties (`$this->x`). This favours precision over recall.
* Dynamic checks only touch endpoints listed in `ACTIVE_CANDIDATES`; add the
  actions/parameters of the plugin under test to extend coverage.
* Error based SQLi detection needs a target that prints database errors
  (`WP_DEBUG` on); otherwise the time based path is exercised.
* Active checks perform real exploitation (uploading a PHP file, `SLEEP()`,
  reading `/etc/passwd`). Only run them against systems you are allowed to test.

