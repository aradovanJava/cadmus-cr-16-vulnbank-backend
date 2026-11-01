# CADMUS VulnBank — mock backend

**Deliberately vulnerable training server** for the VulnBank Mobile app of
**CADMUS-CR-16 Secure Coding Mobile** (BTCMP-02).

> ⚠️ **Training system — sandbox only.** Every weakness in this server is
> deliberate. Never deploy it, never expose it outside the Cyber Range, never
> put real data in it. All users, IBANs and balances are fabricated.

## Why it exists

The Android client `eu.cadmus.vulnbank` talks to `http://vulnbank.local/api/v1`
and opens `http://support.vulnbank.local/help` in its support WebView, but the
course material ships only the client. Without a server, the app's requests go
nowhere and OWASP ZAP has nothing to scan. This server answers exactly the
requests the client makes and follows the course narrative: the client was
trusted to enforce the rules, so the server does not.

## Endpoints

| Method | Path | Used by |
|---|---|---|
| GET | `/api/v1/login?user=…&pass=…` | `ApiClient.login()` (with the client's static `Authorization: Basic …`) |
| POST | `/api/v1/transfer` | `ApiClient.submitTransfer()` (JSON body, `Authorization: Bearer …`) |
| GET | `/api/v1/accounts/<iban>` | account lookup |
| GET | `/api/v1/health` | status |
| GET | `/help` | the support portal loaded by `SupportWebViewActivity` |
| POST | `/v2/ingest` | telemetry sink for `AnalyticsReporter` |

Fabricated accounts mirror the credentials compiled into the client
(`a.novak`, `demo`, `vb_service`) plus an administrator `adm_ops`.

## Running it

In the CR-16 sandbox it runs as a container on MOB1, published on the lab LAN
as `vulnbank.local` and `support.vulnbank.local` (port 80). Locally:

```bash
docker build -t cadmus-vulnbank-backend .
docker run --rm -p 127.0.0.1:8080:8080 cadmus-vulnbank-backend
# or:  pip install -r requirements.txt && python app.py
python -m pytest -q tests     # behaviour checks
```

The weaknesses are marked `TRAINING WEAKNESS` in `app.py`; the instructor
answer key maps them to the course levels.

---

Co-funded by the European Union (Digital Europe Programme, grant agreement
101190006 — CADMUS). Views and opinions expressed are those of the author(s)
only and do not necessarily reflect those of the European Union or HaDEA.
