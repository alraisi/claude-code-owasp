---
name: owasp-api-security
description: Use when building, reviewing, or securing REST, GraphQL, gRPC, or any HTTP API — including endpoint authorization, object/property-level access control, rate limiting, API authentication, SSRF prevention, and third-party API consumption. Covers the OWASP API Security Top 10 2023 (API1–API10). For general web app security use owasp-web-security; for mobile API clients use owasp-mobile-security; for LLM/AI API endpoints also use owasp-llm-security.
---

# OWASP API Security Top 10 2023

Apply these controls when designing, building, reviewing, or testing any API (REST, GraphQL, gRPC, SOAP, webhooks). APIs have a distinct attack surface from traditional web apps: they expose object identifiers directly, often lack server-side state, and trust third-party integrations — making authorization and resource control the dominant risk areas.

> **Scope:** This covers API-specific risks. For general application security (XSS, CSRF, crypto, secrets) use **owasp-web-security**. The two are complementary — most APIs need both.

---

## Quick Reference Table

| # | Risk | Root Cause | Key Mitigation |
|---|------|------------|----------------|
| API1 | Broken Object Level Authorization (BOLA) | Object ID manipulation; no per-object access check | Authorize every object access against user policy |
| API2 | Broken Authentication | Weak/missing auth on endpoints and token flows | Standard auth, MFA, anti-brute-force, validate tokens |
| API3 | Broken Object Property Level Authorization | Excessive data exposure + mass assignment | Validate property-level read/write per user |
| API4 | Unrestricted Resource Consumption | No limits on compute, memory, calls, spend | Rate limits, quotas, timeouts, payload caps |
| API5 | Broken Function Level Authorization (BFLA) | Regular users reach admin/privileged functions | Deny-by-default, role checks on every function |
| API6 | Unrestricted Access to Sensitive Business Flows | Business flow automatable without friction | Detect automation, add business-layer protection |
| API7 | Server Side Request Forgery (SSRF) | API fetches user-supplied URI without validation | Validate URIs, allowlist, disable redirects, isolate |
| API8 | Security Misconfiguration | Missing hardening, patches, TLS, CORS errors | Repeatable hardening, automated config assessment |
| API9 | Improper Inventory Management | Undocumented/old/exposed API versions & hosts | Inventory all hosts & versions, retire old APIs |
| API10 | Unsafe Consumption of APIs | Over-trusting data from third-party APIs | Validate third-party data, TLS, timeouts, allowlist redirects |

---

## API1:2023 — Broken Object Level Authorization (BOLA)

**The #1 API risk.** Attackers manipulate an object ID in the request (path, query, header, or body) to access objects belonging to other users. Object IDs may be sequential integers, UUIDs, or strings — all are easy to find and swap.

**Why it's so common:** The server doesn't fully track client state and relies on client-supplied IDs to decide which object to return. The server response usually reveals whether the request succeeded.

> **Critical distinction:** Comparing the session user ID with the ID parameter is NOT sufficient — that only covers a narrow subset. If a user reaches an endpoint they shouldn't, that's BFLA (API5). BOLA is about manipulating the *object* within an endpoint the user *can* legitimately access.

**Is the API Vulnerable?**
- Any endpoint receiving an object ID and acting on it must check that the logged-in user has permission for *that specific object*.
- Failures lead to unauthorized disclosure, modification, or destruction of data — sometimes full account takeover.

**Attack scenario:** An e-commerce platform exposes `/shops/{shopName}/revenue_data.json`. An attacker enumerates shop names from another endpoint and scripts requests swapping `{shopName}`, harvesting sales data of thousands of stores.

**How To Prevent:**
- Implement an authorization mechanism based on user policies and hierarchy
- Check user-to-object permission in *every* function that uses a client-supplied ID to access a record
- Prefer random, unpredictable GUIDs for record IDs
- Write authorization tests; block deployments that fail them

**Code pattern:**
```python
# UNSAFE: Trusts the client-supplied ID
@app.route('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    return db.get_order(order_id)  # ANY order, any user

# SAFE: Verify ownership of THIS object
@app.route('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    order = db.get_order(order_id)
    if order is None or order.user_id != current_user.id:
        abort(404)  # 404 not 403 — don't confirm existence
    return order
```

**References:** CWE-285 (Improper Authorization), CWE-639 (Authorization Bypass Through User-Controlled Key), OWASP Authorization Cheat Sheet.

---

## API2:2023 — Broken Authentication

Authentication endpoints are exposed to everyone and are a prime target. Treat "forgot/reset password" flows the same as login.

**Is the API Vulnerable?**
- Permits credential stuffing (no defense against valid username/password lists)
- Permits brute force on a single account (no captcha/lockout)
- Permits weak passwords
- Sends auth tokens or passwords in the URL
- Allows sensitive operations (change email/password) without re-confirming password
- Doesn't validate token authenticity
- Accepts unsigned/weakly-signed JWTs (`{"alg":"none"}`)
- Doesn't validate JWT expiration
- Uses plaintext, unencrypted, or weakly-hashed passwords
- Uses weak encryption keys
- Microservice: reachable without authentication, or uses weak/predictable tokens

**Attack scenario:** A GraphQL login has rate limiting (3/min), but the attacker uses **query batching** to send dozens of password guesses in a single HTTP request, bypassing the per-request rate limit.

**How To Prevent:**
- Map *all* authentication flows (mobile, web, deep links, one-click) — ask engineers what you missed
- Understand your mechanisms: OAuth is not authentication; API keys are not authentication
- Don't reinvent auth, token generation, or password storage — use standards
- Treat credential recovery endpoints as login endpoints (brute force, rate limit, lockout)
- Require re-authentication for sensitive operations (email change, 2FA phone change)
- Implement MFA where possible
- Implement anti-brute-force *stricter* than normal rate limits; add account lockout/captcha and weak-password checks
- API keys are for client identification, not user authentication

**Code pattern — JWT validation:**
```python
import jwt

# UNSAFE: Accepts any algorithm, including "none"
payload = jwt.decode(token, verify=False)

# SAFE: Pin algorithm, verify signature and expiry
try:
    payload = jwt.decode(
        token, PUBLIC_KEY,
        algorithms=["RS256"],          # never allow "none"
        options={"require": ["exp", "iat"], "verify_exp": True}
    )
except jwt.InvalidTokenError:
    abort(401)
```

**References:** CWE-204 (Observable Response Discrepancy), CWE-307 (Improper Restriction of Excessive Authentication Attempts), OWASP Authentication Cheat Sheet.

---

## API3:2023 — Broken Object Property Level Authorization

Merges the old API3:2019 (Excessive Data Exposure) and API6:2019 (Mass Assignment). Root cause: missing or improper validation at the **property** level — either returning properties the user shouldn't read, or accepting properties the user shouldn't write.

**Is the API Vulnerable?**
- **Excessive data exposure:** Endpoint returns *all* object properties (relying on the client to filter), exposing sensitive fields.
- **Mass assignment:** Endpoint accepts a whole object and writes properties the user shouldn't control (e.g. `role`, `is_admin`, `account_balance`).

**Attack scenario:** A user-profile update endpoint accepts the full JSON object. An attacker adds `"is_admin": true` to the payload, and the API blindly binds it to the model — escalating privileges.

**How To Prevent:**
- Return only the minimum properties the client needs for the specific use case
- Never rely on the client to filter sensitive data
- Explicitly allowlist which properties can be *updated* by the client
- Avoid generic methods that auto-bind all input to object properties
- Enforce schema-based response validation
- Keep returned data structures to the minimum required

**Code pattern — explicit allowlists both directions:**
```python
# UNSAFE: Mass assignment — binds everything the client sends
user.update(**request.json)  # attacker sets is_admin=True

# SAFE: Allowlist writable properties
ALLOWED_UPDATES = {"display_name", "email", "bio"}
updates = {k: v for k, v in request.json.items() if k in ALLOWED_UPDATES}
user.update(**updates)

# UNSAFE: Returns the full object including password_hash, role, internal flags
return jsonify(user.__dict__)

# SAFE: Serialize only the fields appropriate for this caller
return jsonify({"id": user.id, "display_name": user.display_name, "bio": user.bio})
```

**References:** CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes).

---

## API4:2023 — Unrestricted Resource Consumption

Servicing API requests costs bandwidth, CPU, memory, storage — and sometimes real money (SMS, email, phone calls, biometric checks, cloud-metered third-party calls). Without limits, attackers cause DoS or run up costs ("Denial of Wallet").

**Is the API Vulnerable?** Missing or mis-set limits on any of:
- Execution timeouts
- Maximum allocable memory
- Maximum number of file descriptors / processes
- Maximum upload file size
- Number of operations per request (e.g. GraphQL batching)
- Number of records per page
- Third-party service provider spending limits

**Attack scenario:** A "forgot password" flow triggers a back-end call to an SMS provider charging $0.05/message. An attacker scripts tens of thousands of requests, costing the company thousands of dollars in minutes.

**How To Prevent:**
- Use a container/serverless platform that enforces memory, CPU, restart, and process limits
- Set maximum sizes for all incoming parameters and payloads (string length, array size)
- Implement rate limiting per client; define how often and how many records a client may request
- Add server-side validation for query string and request body parameters, especially those controlling result count
- Configure spending limits and billing alerts on all paid third-party integrations
- Limit GraphQL query depth, complexity, and batch size

**Code pattern — GraphQL depth/complexity limiting:**
```python
# Limit query depth and batching to prevent resource exhaustion
from graphql import validate, parse
from graphql_depth_limit import depth_limit

errors = validate(schema, parse(query), [depth_limit(7)])
if errors:
    abort(400, "Query too deep")

# Cap batch size
if isinstance(request.json, list) and len(request.json) > 10:
    abort(400, "Batch too large")
```

**References:** CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400 (Uncontrolled Resource Consumption), CWE-799 (Improper Control of Interaction Frequency).

---

## API5:2023 — Broken Function Level Authorization (BFLA)

Complex role hierarchies and unclear separation between regular and administrative functions lead to authorization flaws. Attackers reach functions (not just objects) they shouldn't — accessing other users' resources or admin operations.

**Is the API Vulnerable?**
- Can a regular user access administrative endpoints?
- Can a user perform a sensitive action (create/modify/delete) simply by changing the HTTP method (e.g. `GET` → `DELETE`)?
- Can a user in group X reach a group-Y-only function by guessing the URL (e.g. `/api/v1/users/export_all`)?

> Predictable admin routes + missing role checks = BFLA. Unlike BOLA (object-level), this is about reaching the *function* itself.

**How To Prevent:**
- Deny all access by default; require explicit grants per role for every function
- Review every endpoint for function-level flaws, keeping business logic and group hierarchy in mind
- Have all administrative controllers inherit from an abstract admin controller enforcing role-based authorization
- Ensure admin functions inside regular controllers still check the user's group/role

**Code pattern:**
```python
# UNSAFE: Admin endpoint with no role check — reachable by URL guessing
@app.route('/api/v1/users/export_all', methods=['GET'])
@login_required
def export_all_users():
    return db.all_users()

# SAFE: Deny by default, explicit role grant
@app.route('/api/v1/users/export_all', methods=['GET'])
@login_required
@require_role("admin")        # decorator enforces RBAC, denies otherwise
def export_all_users():
    return db.all_users()
```

**References:** CWE-285 (Improper Authorization), OWASP "Missing Function Level Access Control."

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

The API exposes a business flow (buying a ticket, posting a comment, making a reservation) without compensating for the harm of *excessive automated* use. This is not necessarily an implementation bug — the flow works as designed, but lacks anti-automation protection.

**Is the API Vulnerable?** A sensitive business flow is exposed where automation causes harm:
- **Purchasing flow:** attacker buys all stock of a high-demand item to scalp/resell
- **Comment/post flow:** attacker spams the system
- **Reservation flow:** attacker reserves all slots, blocking legitimate users

**How To Prevent (two layers):**
- **Business layer:** Identify which flows harm the business if used excessively
- **Engineering layer:** Choose protections to mitigate the business risk:
  - Device fingerprinting to deny service to headless browsers
  - Human detection (captcha, biometric solutions like Apple/Google attestation)
  - Detect and block known bot/proxy/VPN IP patterns
  - Restrict access to APIs consumed directly by machines (e.g. block headless flows)
  - Non-technical: e.g. ship high-demand items a few days after purchase, allow cancellation window

> Rate limiting alone is often insufficient — a distributed attack stays under per-IP limits. Layer business-flow protection on top.

**References:** OWASP Automated Threats to Web Applications, CWE-799 (Improper Control of Interaction Frequency).

---

## API7:2023 — Server Side Request Forgery (SSRF)

Occurs when an API fetches a remote resource using a user-supplied URI **without validating it**. The attacker forces the application to send a crafted request to an unexpected destination — even through firewalls or VPNs — reaching internal services, cloud metadata endpoints, etc.

**Is the API Vulnerable?** Any feature that fetches a remote resource by client-supplied URL (webhooks, file imports by URL, image fetchers, SSO metadata) without validation is vulnerable.

**Attack scenario:** An API accepts an image URL to download for a user profile. The attacker supplies `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (cloud metadata endpoint) and exfiltrates cloud credentials.

**How To Prevent:**
- **Isolate** the resource-fetching mechanism in your network (it's meant for remote, not internal, resources)
- Use **allowlists** of: remote origins users can fetch from, URL schemes and ports, accepted media types
- **Disable HTTP redirections** (or validate each hop)
- Use a well-tested, maintained URL parser to avoid parser-inconsistency exploits
- Validate and sanitize all client-supplied input data
- Do **not** send raw responses back to clients
- Block access to internal/private IP ranges and cloud metadata endpoints (link-local 169.254.0.0/16, RFC1918)

**Code pattern:**
```python
import ipaddress
from urllib.parse import urlparse
import socket

ALLOWED_SCHEMES = {"https"}
BLOCKED_NETS = [ipaddress.ip_network(n) for n in
    ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
     "192.168.0.0/16", "169.254.0.0/16", "::1/128")]

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except (socket.gaierror, ValueError):
        return False
    return not any(ip in net for net in BLOCKED_NETS)

# Fetch only after validation, and disable redirects
if not is_safe_url(user_url):
    abort(400, "URL not allowed")
resp = requests.get(user_url, allow_redirects=False, timeout=5)
```

**References:** CWE-918 (Server-Side Request Forgery), Snyk "URL confusion vulnerabilities in the wild."

---

## API8:2023 — Security Misconfiguration

APIs and their supporting stacks have complex, customizable configurations. Missed or non-best-practice settings open multiple attack vectors.

**Is the API Vulnerable?**
- Security hardening missing anywhere in the API stack, or improper cloud-service permissions
- Latest security patches missing or systems out of date
- Unnecessary features enabled (extra HTTP verbs, verbose logging)
- Discrepancies in how servers in the HTTP chain process requests (request smuggling)
- TLS missing
- Security/cache-control directives not sent to clients
- CORS policy missing or improperly set
- Error messages leaking stack traces or sensitive info

**How To Prevent:**
- A **repeatable hardening process** for fast, locked-down deployments
- A task to **review and update configs** across the whole stack: orchestration files, API components, cloud services (e.g. S3 bucket permissions)
- An **automated process** to continuously assess config effectiveness in all environments
- Encrypt all API communications (TLS), internal and public alike
- Be explicit about allowed HTTP verbs per endpoint; disable all others
- For browser clients, send appropriate security headers and a restrictive CORS policy
- Restrict incoming content types to those actually needed
- Ensure all servers in the HTTP chain process requests uniformly (avoid desync/smuggling)
- Define and enforce response schemas, including error responses, to prevent leaking traces

**Code pattern — CORS and headers:**
```python
# UNSAFE: Wildcard CORS with credentials
response.headers["Access-Control-Allow-Origin"] = "*"
response.headers["Access-Control-Allow-Credentials"] = "true"  # dangerous combo

# SAFE: Explicit allowlist
ALLOWED_ORIGINS = {"https://app.example.com"}
origin = request.headers.get("Origin")
if origin in ALLOWED_ORIGINS:
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"

# Security headers
response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
response.headers["X-Content-Type-Options"] = "nosniff"
response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
```

**References:** CWE-2, CWE-16 (Configuration), CWE-209 (Error Message Info Leak), CWE-319 (Cleartext Transmission), CWE-388 (Error Handling), CWE-444 (HTTP Request Smuggling), CWE-942 (Permissive CORS), NIST SP 800-123.

---

## API9:2023 — Improper Inventory Management

APIs expose more endpoints than traditional web apps, making clean, current documentation and host inventory critical. Old API versions and exposed debug endpoints are frequent breach entry points.

**Is the API Vulnerable?**
- Unclear purpose of an API host; no answers to "what environment, who has access, what version"
- No documentation, or outdated documentation
- No retirement plan for each API version
- Missing or outdated host inventory
- A "sensitive data flow" where the API shares data with a third party with no business justification, inventory, or visibility

**How To Prevent:**
- Inventory all API hosts; document environment (prod/staging/test/dev), network access scope (public/internal/partners), and version
- Inventory integrated services; document their role, data exchanged (data flow), and sensitivity
- Document all API aspects: authentication, errors, redirects, rate limiting, CORS, endpoints with parameters/requests/responses
- Generate docs automatically via open standards (OpenAPI); build docs in CI/CD
- Make API documentation available only to authorized users
- Apply API-security protections to *all* exposed versions, not just current production
- Avoid production data in non-production deployments; if unavoidable, give those endpoints production-grade security
- When new versions add security improvements, risk-analyze older versions: backport, or force migration and retire the old version quickly

**References:** CWE-1059 (Insufficient/Incomplete Documentation).

---

## API10:2023 — Unsafe Consumption of APIs

Developers tend to trust data from third-party APIs more than user input, applying weaker security to it. Attackers target the integrated third-party services rather than attacking the target API directly.

**Is the API Vulnerable?** Your API:
- Interacts with other APIs over an unencrypted channel
- Doesn't properly validate/sanitize data from other APIs before processing or passing it downstream
- Blindly follows redirections
- Doesn't limit resources allocated to process third-party responses
- Doesn't implement timeouts for third-party interactions

**Attack scenario:** A service integrates a third-party API to enrich data. The attacker compromises or spoofs the third party, returning a malicious redirect or oversized payload. The target API blindly follows the redirect (→ SSRF) or exhausts resources parsing the response.

**How To Prevent:**
- Assess the API-security posture of service providers before integrating
- Ensure all API interactions happen over TLS
- Always validate and sanitize data received from integrated APIs before using it
- Maintain an allowlist of locations integrated APIs may redirect to; do not blindly follow redirects
- Implement timeouts and resource limits for third-party interactions
- Treat third-party data with the same suspicion as user input

**Code pattern:**
```python
# UNSAFE: Trusts and follows third-party response blindly
data = requests.get(partner_api_url).json()
db.save(data)  # unvalidated, possibly malicious

# SAFE: TLS enforced, timeout, no auto-redirect, validate before use
resp = requests.get(
    partner_api_url, timeout=5, allow_redirects=False,
    verify=True  # enforce TLS cert validation
)
resp.raise_for_status()
data = resp.json()
validated = PartnerSchema().load(data)   # schema validation
db.save(validated)
```

**References:** CWE-20 (Improper Input Validation), CWE-200 (Sensitive Info Exposure), CWE-319 (Cleartext Transmission).

---

## API Security Review Checklist

**Authorization (API1, API3, API5) — the dominant API risk area**
- [ ] Every endpoint taking an object ID checks user-to-object permission (BOLA)
- [ ] Object IDs are random/unpredictable (GUIDs) where feasible
- [ ] Property-level: client cannot read sensitive fields it shouldn't (no excessive exposure)
- [ ] Property-level: client cannot write privileged fields (no mass assignment) — explicit allowlist
- [ ] Function-level: deny-by-default; admin/privileged functions enforce role checks (BFLA)
- [ ] HTTP method changes (GET→DELETE) cannot bypass function authorization

**Authentication (API2)**
- [ ] Standard auth libraries used; no custom token/password schemes
- [ ] JWTs: algorithm pinned (no "none"), signature verified, expiry checked
- [ ] Anti-brute-force + lockout/captcha on login AND password-reset endpoints
- [ ] Sensitive operations require re-authentication
- [ ] MFA available; no tokens/passwords in URLs
- [ ] API keys used only for client identification, not user auth

**Resource & Business Protection (API4, API6)**
- [ ] Rate limits and per-client quotas enforced
- [ ] Payload size, array size, and string length caps in place
- [ ] GraphQL query depth, complexity, and batch size limited
- [ ] Timeouts and memory/process limits configured
- [ ] Spending limits + alerts on paid third-party integrations
- [ ] Sensitive business flows have anti-automation protection beyond rate limiting

**SSRF & Third-Party (API7, API10)**
- [ ] User-supplied URIs validated against an allowlist before fetching
- [ ] Internal IP ranges and cloud metadata endpoints blocked
- [ ] HTTP redirects disabled or each hop validated
- [ ] Third-party API data validated/sanitized before use
- [ ] All API-to-API communication over TLS with cert validation
- [ ] Timeouts and resource limits on third-party responses

**Configuration & Inventory (API8, API9)**
- [ ] Repeatable hardening process; automated config assessment across environments
- [ ] TLS enforced on all communications (internal and public)
- [ ] CORS policy explicit (no wildcard + credentials); security headers set
- [ ] Only required HTTP verbs enabled per endpoint
- [ ] Error responses schema-enforced; no stack traces leaked
- [ ] All API hosts and versions inventoried with environment and access scope
- [ ] Old API versions retired or protected; debug endpoints not exposed
- [ ] OpenAPI docs auto-generated in CI/CD, restricted to authorized users
- [ ] No production data in non-production environments

---

## When to Apply This Skill

- Designing or reviewing any REST, GraphQL, gRPC, or HTTP API
- Implementing API authentication and authorization
- Building API endpoints that take object IDs or accept object payloads
- Adding rate limiting, quotas, or resource controls
- Implementing features that fetch user-supplied URLs (SSRF risk)
- Integrating or consuming third-party APIs
- API gateway / API management configuration
- API penetration testing or security assessment

For general application security (XSS, CSRF, injection, crypto, secrets), pair with **owasp-web-security**. For mobile apps consuming APIs, use **owasp-mobile-security**. For LLM/AI API endpoints, also use **owasp-llm-security**. For language-specific issues, use **owasp-language-quirks**.
