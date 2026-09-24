#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dependency free stand-in for the vulnerable WordPress lab.

The scanner's dynamic checks are validated against the real Docker lab, but
pulling container images is not always possible. This module emulates the
*observable behaviour* of env/vulnerable-plugin/vuln-core.php (same endpoints,
same responses, same side effects such as the SLEEP() delay and the executed
upload) so that `python tests/run_tests.py --mock` can validate the dynamic
checks offline.

It implements only the subset of WordPress endpoints the scanner probes.
"""

import os
import re
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "vscan_mock_uploads")

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")

HOME = ('<!DOCTYPE html><html><head><meta name="generator" '
        'content="WordPress 6.4.2" /></head><body><h1>Vuln Lab</h1></body></html>')

XMLRPC_METHODS = ("system.listMethods", "pingback.ping", "wp.getUsersBlogs",
                  "system.multicall")


def _multipart_field(raw, field_name):
    """Return (filename, content) for a field inside a multipart body."""
    pattern = (r'name="' + re.escape(field_name) +
               r'"[^;]*;\s*filename="([^"]*)"')
    match = re.search(pattern, raw)
    if not match:
        return None, None
    start = raw.find("\r\n\r\n", match.end())
    if start == -1:
        return match.group(1), ""
    start += 4
    end = raw.find("\r\n--", start)
    return match.group(1), raw[start:end if end != -1 else len(raw)]


class _Handler(BaseHTTPRequestHandler):
    server_version = "MockWordPress/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the test output clean
        pass

    # ------------------------------------------------------------------ utils
    def _respond(self, code, body="", ctype="text/html; charset=utf-8",
                 headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _query(self):
        return parse_qs(urlparse(self.path).query)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length).decode("utf-8", "replace")

    def _params(self):
        """Merge query string, urlencoded body and multipart fields."""
        params = {k: v[0] for k, v in self._query().items()}
        ctype = self.headers.get("Content-Type", "")
        if ctype.startswith("application/x-www-form-urlencoded"):
            params.update({k: v[0] for k, v in parse_qs(self._read_body()).items()})
        elif ctype.startswith("multipart/form-data"):
            raw = self._read_body()
            params["__raw__"] = raw
            for name, value in re.findall(r'name="([^"]+)"\r\n\r\n([^\r\n]*)', raw):
                params.setdefault(name, value)
        return params

    # ------------------------------------------------------- vulnerable ajax
    def _ajax(self, params):
        action = params.get("action", "")
        if action == "vulnlab_exec":
            cmd = params.get("cmd", "")
            # Emulate system( 'id; ' . $cmd ): "echo X" prints X, "sleep N" waits.
            sleep = re.search(r"sleep\s+([0-9]+)", cmd, re.IGNORECASE)
            if sleep:
                time.sleep(min(int(sleep.group(1)), 8))
            output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            echo = re.search(r"echo\s+([A-Za-z0-9_]+)", cmd)
            if echo:
                output += echo.group(1) + "\n"
            self._respond(200, "VULNLAB-OK:" + output)
        elif action == "vulnlab_search":
            if re.search(r"sleep\s*\(", params.get("u", ""), re.IGNORECASE):
                time.sleep(4)
            self._respond(200, "VULNLAB-OK:1")
        elif action == "vulnlab_read":
            filename = params.get("file", "")
            if filename.endswith("passwd"):
                self._respond(200, "VULNLAB-OK:" + PASSWD)
            elif filename.endswith("wp-config.php"):
                self._respond(200, "VULNLAB-OK:define('DB_NAME','wordpress');"
                                   "define('DB_PASSWORD','labsecret');")
            else:
                self._respond(200, "VULNLAB-OK:")
        elif action == "vulnlab_xss":
            self._respond(200, '<span class="vulnlab-msg">' +
                          params.get("msg", "") + "</span>")
        elif action == "vulnlab_redirect":
            self._respond(302, "", headers={"Location": params.get("url", "")})
        elif action == "vulnlab_unpack":
            data = params.get("data", "")
            self._respond(200, "VULNLAB-OK:" +
                          ("object" if data.startswith("O:") else "string"))
        elif action == "vulnlab_upload":
            self._respond(200, "VULNLAB-UPLOADED:" +
                          self._store_upload(params.get("__raw__", "")))
        else:
            self._respond(200, "0")

    def _store_upload(self, raw):
        name, content = _multipart_field(raw, "shell")
        if name is None:
            return "no-file"
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        with open(os.path.join(UPLOAD_DIR, os.path.basename(name)), "w",
                  encoding="utf-8") as handle:
            handle.write(content or "")
        return name

    def _serve_upload(self, name):
        path = os.path.join(UPLOAD_DIR, os.path.basename(name))
        if not os.path.isfile(path):
            self._respond(404, "Not found")
            return
        with open(path, encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        # A vulnerable server *executes* the uploaded PHP instead of printing it.
        echo = re.search(r'echo\s+"([^"]*)"', content)
        self._respond(200, echo.group(1) if echo else content)

    def _xmlrpc(self):
        body = self._read_body()
        if "system.listMethods" not in body:
            self._respond(200, '<?xml version="1.0"?><methodResponse/>',
                          ctype="text/xml")
            return
        values = "".join("<value><string>%s</string></value>" % m
                         for m in XMLRPC_METHODS)
        self._respond(200,
                      '<?xml version="1.0"?><methodResponse><params><param>'
                      '<value><array><data>%s</data></array></value></param>'
                      '</params></methodResponse>' % values, ctype="text/xml")


    # ---------------------------------------------------------------- routing
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if parse_qs(parsed.query).get("author"):
            # emulates the canonical redirect of /?author=1
            self._respond(302, "", headers={"Location": "/author/admin/"})
            return
        if path in ("/", "/index.php"):
            self._respond(200, HOME)
        elif path == "/wp-login.php":
            self._respond(200, "<html><body>login</body></html>")
        elif path == "/readme.html":
            self._respond(200, "<html><body><h1>WordPress</h1>"
                               "<p>Version 6.4.2</p></body></html>")
        elif path == "/license.txt":
            self._respond(200, "WordPress - Web publishing software")
        elif path == "/.git/config":
            self._respond(200, "[core]\n\trepositoryformatversion = 0\n"
                               "\tfilemode = true\n")
        elif path == "/.env":
            self._respond(200, "DB_NAME=wordpress\nDB_PASSWORD=labsecret\n")
        elif path == "/wp-content/debug.log":
            self._respond(200, "[12-Jan-2026 10:00:00 UTC] PHP Fatal error: "
                               "Uncaught Error: Call to undefined function()\n")
        elif path == "/wp-content/plugins/":
            self._respond(200, "<html><head><title>Index of /wp-content/plugins"
                               "</title></head><body><h1>Index of "
                               "/wp-content/plugins</h1></body></html>")
        elif path == "/wp-json/wp/v2/users":
            self._respond(200, '[{"id":1,"slug":"admin","name":"admin"}]',
                          ctype="application/json")
        elif path == "/wp-admin/admin-ajax.php":
            self._ajax(self._params())
        elif path.startswith("/wp-content/uploads/"):
            self._serve_upload(path.rsplit("/", 1)[-1])
        elif path.rstrip("/") == "/author/admin":
            self._respond(200, '<body class="archive author author-admin">'
                               'author: admin</body>')
        elif path == "/xmlrpc.php":
            self._respond(405, "XML-RPC server accepts POST requests only.")
        else:
            self._respond(404, "Not found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/xmlrpc.php":
            self._xmlrpc()
        elif path == "/wp-admin/admin-ajax.php":
            self._ajax(self._params())
        else:
            self._read_body()  # keep the connection clean
            self._respond(404, "Not found")


def start(port=0):
    """Start the mock in a background thread, return (httpd, base_url)."""
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, "http://127.0.0.1:{}".format(httpd.server_address[1])


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mock vulnerable WordPress target")
    parser.add_argument("--port", type=int, default=8888)
    args = parser.parse_args()
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print("Mock WordPress listening on http://127.0.0.1:{}".format(
        httpd.server_address[1]))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main()

