"""
CADMUS VulnBank - mock backend for the VulnBank Mobile training app
====================================================================
CADMUS-CR-16 Secure Coding Mobile - Cyber Range sandbox only.

DELIBERATELY VULNERABLE TRAINING SERVER - DO NOT DEPLOY.

The Android client (eu.cadmus.vulnbank) talks to

    http://vulnbank.local/api/v1/login?user=...&pass=...   (GET)
    http://vulnbank.local/api/v1/transfer                  (POST, JSON)
    http://support.vulnbank.local/help                      (support WebView)

This server answers those requests so that the client's traffic is real and
OWASP ZAP has something to scan. It mirrors the course narrative: the client
was trusted to enforce the rules, so the server does not. Every weakness is
deliberate and marked "TRAINING WEAKNESS". All data is fabricated.

It listens on 0.0.0.0 inside its container; the sandbox publishes it only on
the lab LAN as vulnbank.local / support.vulnbank.local.
"""
import base64
import json
import os
import sys
import traceback

from flask import Flask, Response, jsonify, request

VERSION = "1.2.0-TRAINING"
app = Flask(__name__)

# --- fabricated data -----------------------------------------------------------
# TRAINING WEAKNESS: the server's user store matches the credentials compiled
# into the client (LoginActivity), including the maintenance account.
USERS = {
    "a.novak":    {"password": "Spring2024!",      "role": "CUSTOMER", "iban": "HR0000000000000000001"},
    "demo":       {"password": "demo",             "role": "CUSTOMER", "iban": "HR0000000000000000002"},
    "vb_service": {"password": "Sup3rS3cret!2024", "role": "SERVICE",  "iban": "HR0000000000000000003"},
    "adm_ops":    {"password": "Admin2024!",       "role": "ADMIN",    "iban": "HR0000000000000000004"},
}
ACCOUNTS = {
    "HR0000000000000000001": {"owner": "Ana Novak",       "balance": 12450.00},
    "HR0000000000000000002": {"owner": "Demo Customer",   "balance": 820.50},
    "HR0000000000000000003": {"owner": "VulnBank Ops",    "balance": 0.00},
    "HR0000000000000000004": {"owner": "Operations Desk", "balance": 250000.00},
    "HR0000000000000000099": {"owner": "Unknown payee",   "balance": 10.00},
}
TRANSACTIONS = []

# The client sends "Authorization: Basic dnVsbmJhbms6VnVsbkIhbmsyMDI0" on login.
# TRAINING WEAKNESS: one static client credential shared by every install.
CLIENT_BASIC = "Basic " + base64.b64encode(b"vulnbank:VulnB!ank2024").decode()


def _token_for(username, role):
    # TRAINING WEAKNESS: the "session token" is base64(username:role) - no
    # signature, no expiry, editable by the client.
    return base64.b64encode(f"{username}:{role}".encode()).decode()


@app.after_request
def _headers(resp):
    # TRAINING WEAKNESS: no security headers at all, and the server announces
    # its build in every response.
    resp.headers["X-VulnBank-Build"] = VERSION
    return resp


@app.errorhandler(Exception)
def _error(exc):
    # TRAINING WEAKNESS: stack traces are returned to the caller.
    return jsonify(error=str(exc), trace=traceback.format_exc()), 500


# --- API -----------------------------------------------------------------------
@app.get("/")
def index():
    return Response(
        "<!doctype html><html><head><title>VulnBank API</title></head><body>"
        "<h1>VulnBank API " + VERSION + "</h1>"
        "<p>Training backend for the VulnBank Mobile app. Endpoints: "
        "<a href='/api/v1/health'>/api/v1/health</a>, "
        "<a href='/api/v1/login?user=demo&amp;pass=demo'>/api/v1/login</a>, "
        "<a href='/api/v1/accounts/HR0000000000000000002'>/api/v1/accounts/&lt;iban&gt;</a>, "
        "<a href='/help'>/help</a> (support portal).</p></body></html>",
        mimetype="text/html")


@app.get("/api/v1/health")
def health():
    # TRAINING WEAKNESS: internal details on an unauthenticated endpoint.
    return jsonify(status="UP", version=VERSION, users=len(USERS),
                   python=sys.version.split()[0])


@app.get("/api/v1/login")
def login():
    """Credentials arrive in the query string, over plain HTTP (client M5/M6)."""
    if request.headers.get("Authorization") != CLIENT_BASIC:
        return jsonify(error="missing or invalid client credential"), 401
    user = request.args.get("user", "")
    pwd = request.args.get("pass", "")
    entry = USERS.get(user)
    # TRAINING WEAKNESS: distinguishable answers reveal which usernames exist,
    # and there is no attempt limit.
    if entry is None:
        return jsonify(error="unknown user " + user), 404
    if entry["password"] != pwd:
        return jsonify(error="wrong password"), 401
    return jsonify(token=_token_for(user, entry["role"]), role=entry["role"],
                   iban=entry["iban"], balance=ACCOUNTS[entry["iban"]]["balance"])


@app.post("/api/v1/transfer")
def transfer():
    """The server-side half of the CR1 authorisation finding.

    The client builds this JSON by string concatenation and enforces the daily
    limit itself. TRAINING WEAKNESSES on this side:
      * any non-empty bearer token is accepted - nobody is authenticated;
      * no limit is enforced, and negative amounts are accepted;
      * duplicate keys are resolved "last one wins", so a crafted IBAN that
        injects ',"from":"..."' moves money out of someone else's account.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or len(auth) <= len("Bearer "):
        return jsonify(error="missing bearer token"), 401
    body = json.loads(request.get_data(as_text=True) or "{}")
    src, dst = body.get("from", ""), body.get("to", "")
    amount = float(body.get("amount", "0"))
    if src not in ACCOUNTS:
        return jsonify(error="unknown source account " + src), 404
    ACCOUNTS[src]["balance"] -= amount
    if dst in ACCOUNTS:
        ACCOUNTS[dst]["balance"] += amount
    TRANSACTIONS.append({"from": src, "to": dst, "amount": amount})
    return jsonify(status="ACCEPTED", reference=f"TX{len(TRANSACTIONS):06d}",
                   source_balance=ACCOUNTS[src]["balance"])


@app.get("/api/v1/accounts/<iban>")
def account(iban):
    # TRAINING WEAKNESS: no authentication and no ownership check (IDOR).
    acct = ACCOUNTS.get(iban)
    if acct is None:
        return jsonify(error="no such account " + iban), 404
    return jsonify(iban=iban, owner=acct["owner"], balance=acct["balance"],
                   transactions=[t for t in TRANSACTIONS if iban in (t["from"], t["to"])])


@app.post("/v2/ingest")
def ingest():
    # Telemetry sink for AnalyticsReporter (metrics.partner-analytics.local).
    return ("", 204)


# --- support portal (loaded by SupportWebViewActivity) -------------------------
@app.get("/help")
def help_page():
    q = request.args.get("q", "")
    # TRAINING WEAKNESS: the search term is reflected without encoding, and the
    # page uses the app's JavaScript bridge to display the user's session.
    return Response(
        "<!doctype html><html><head><title>VulnBank Support</title></head><body>"
        "<h1>VulnBank Support</h1>"
        "<p id='who'>Signed in as: <span id='user'>(unknown)</span></p>"
        "<form action='/help'><input name='q' value='" + q + "'>"
        "<button>Search help</button></form>"
        + ("<p>Results for: " + q + "</p>" if q else "") +
        "<ul><li>How do I reset my PIN?</li><li>Transfer limits</li></ul>"
        "<script>try{document.getElementById('user').textContent="
        "window.VulnBankBridge.getSessionToken();}catch(e){}</script>"
        "</body></html>",
        mimetype="text/html")


if __name__ == "__main__":
    # Sandbox only: the container is published on the lab LAN, never beyond.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), threaded=True)
