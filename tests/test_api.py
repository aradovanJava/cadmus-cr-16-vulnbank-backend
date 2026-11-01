"""Behaviour checks for the training backend: the deliberate weaknesses are
present and the endpoints the Android client calls answer as it expects."""
import base64
import importlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASIC = "Basic " + base64.b64encode(b"vulnbank:VulnB!ank2024").decode()


def client():
    import app as a
    importlib.reload(a)          # fresh in-memory data per test
    return a.app.test_client()


def test_login_as_the_client_does():
    r = client().get("/api/v1/login?user=a.novak&pass=Spring2024!", headers={"Authorization": BASIC})
    assert r.status_code == 200 and r.get_json()["role"] == "CUSTOMER"


def test_login_enumeration():
    c = client()
    assert c.get("/api/v1/login?user=nobody&pass=x", headers={"Authorization": BASIC}).status_code == 404
    assert c.get("/api/v1/login?user=demo&pass=x", headers={"Authorization": BASIC}).status_code == 401


def test_transfer_as_the_client_sends_it():
    body = '{"from":"HR0000000000000000001","to":"HR0000000000000000099","amount":"100.00"}'
    r = client().post("/api/v1/transfer", data=body, headers={"Authorization": "Bearer 0123456789abcdef",
                                                             "Content-Type": "application/json"})
    assert r.status_code == 200 and r.get_json()["status"] == "ACCEPTED"


def test_transfer_has_no_limit_and_accepts_negative():
    c = client()
    for amount in ("50000.00", "-500"):
        body = json.dumps({"from": "HR0000000000000000002", "to": "HR0000000000000000099", "amount": amount})
        assert c.post("/api/v1/transfer", data=body, headers={"Authorization": "Bearer x"}).status_code == 200


def test_json_injection_through_the_iban():
    # What ApiClient builds when the destination IBAN carries an injected field.
    to = 'HR0000000000000000099","from":"HR0000000000000000004'
    body = '{"from":"HR0000000000000000001","to":"' + to + '","amount":"1000"}'
    c = client()
    r = c.post("/api/v1/transfer", data=body, headers={"Authorization": "Bearer x"})
    assert r.status_code == 200
    assert c.get("/api/v1/accounts/HR0000000000000000004").get_json()["balance"] == 249000.0


def test_idor_and_reflection():
    c = client()
    assert c.get("/api/v1/accounts/HR0000000000000000001").status_code == 200
    assert b"<script>x</script>" in c.get("/help?q=<script>x</script>").data
