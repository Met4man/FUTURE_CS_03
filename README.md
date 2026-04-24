# API Security Assessment - OWASP crAPI

Academic penetration testing report conducted against [OWASP crAPI](https://github.com/OWASP/crAPI) (Completely Ridiculous API) as part of an internship at **Future Interns**, Institute of Finance Management (IFM), Dar es Salaam.

---

## Assessment Overview

| Field | Details |
|---|---|
| **Target** | OWASP crAPI — Completely Ridiculous API |
| **Environment** | Docker (`localhost:8888`) |
| **Author** | David Msekena |
| **Institution** | Institute of Finance Management (IFM), Dar es Salaam |
| **Programme** | BSc Cybersecurity |
| **Assessment Type** | Manual API Security Assessment / Penetration Testing |
| **Framework** | OWASP API Security Top 10 (2023) |
| **Date** | April 2026 |
| **Classification** | Confidential — Academic Use Only |

---

## Tools Used

| Tool | Purpose |
|---|---|
| **Postman** | API request crafting, vulnerability testing, collection management |
| **Burp Suite Community** | HTTP interception, request replay, JWT analysis |
| **Browser DevTools** (Chrome/Firefox) | Network tab reconnaissance, endpoint discovery, token capture |
| **MailHog** (`localhost:8025`) | Email interception, VIN/PIN capture |
| **Docker** | Running the crAPI target environment |

---

## Vulnerability Summary

| # | Vulnerability | OWASP Category | Severity | Status |
|---|---|---|---|---|
| 1 | API Endpoint Discovery | API9:2023 | Medium | Confirmed |
| 2 | Broken Object Level Authorization (BOLA) | API1:2023 | High | Confirmed |
| 3 | Broken Authorization — Data Access | API1:2023 | High | Confirmed |
| 4 | Excessive Data Exposure / Info Disclosure | API3:2023 | High | Confirmed |
| 5 | Weak Tokens — JWT & OTP Brute Force | API2:2023 | Critical | Confirmed |
| 6 | Missing Rate Limiting | API4:2023 | High | Confirmed |
| 7 | Mass Assignment / Input Validation Failure | API6:2023 | Critical | Confirmed |

---

## Findings

### 1. API Endpoint Discovery
**Severity:** Medium &nbsp;|&nbsp; **OWASP:** API9:2023

Internal API endpoints were enumerated passively by observing the browser's Network tab during normal application use. Routes for products, orders, vehicles, and community posts were fully visible in plaintext with no obfuscation.

**Affected endpoints:**
```
GET /workshop/api/shop/products
GET /workshop/api/shop/orders
```

**Remediation:**
- Ensure all sensitive routes require authentication before returning data
- Implement API gateway monitoring to detect automated enumeration
- Avoid verbose API paths that expose internal object or data structure names

---

### 2. Broken Object Level Authorization (BOLA / IDOR)
**Severity:** High &nbsp;|&nbsp; **OWASP:** API1:2023

The API performs no server-side ownership check when retrieving vehicle location data. Substituting another user's `vehicleId` in the URL returns their full vehicle record with `200 OK` — including GPS coordinates, full name, and email address.

**Affected endpoint:**
```
GET /identity/api/v2/vehicle/{vehicleId}/location
```

**Remediation:**
- Enforce ownership checks server-side on every resource request
- Log and alert on cross-account access attempts
- Replace sequential or guessable IDs with UUIDs

---

### 3. Broken Authorization — Accessing Other Users' Data
**Severity:** High &nbsp;|&nbsp; **OWASP:** API1:2023

The same authorization failure extends to the general vehicle data endpoint. Any authenticated user can retrieve another user's vehicle data by iterating over car IDs, enabling mass PII harvesting.

**Affected endpoint:**
```
GET /workshop/api/vehicles/{carId}
```

**Remediation:**
- Validate the session owner against the resource owner on every request
- Return `403 Forbidden` rather than `404` on unauthorized access to prevent enumeration

---

### 4. Excessive Data Exposure / Information Disclosure
**Severity:** High &nbsp;|&nbsp; **OWASP:** API3:2023

Multiple endpoints return significantly more data than the UI consumes. The community posts endpoint exposes email addresses, `vehicleId` UUIDs, and internal metadata for all post authors. The vehicle location endpoint bundles owner PII alongside GPS coordinates.

**Affected endpoints:**
```
GET /community/api/v2/community/posts/recent
GET /identity/api/v2/vehicle/{id}/location
GET /identity/api/v2/user/dashboard
```

**Remediation:**
- Return only fields explicitly required by the client — implement a server-side response allowlist
- Never rely on the frontend to filter sensitive fields
- Regularly audit API responses for unintended data leakage

---

### 5. Weak Tokens — JWT Algorithm Confusion & OTP Brute Force
**Severity:** Critical &nbsp;|&nbsp; **OWASP:** API2:2023

The application accepts JWTs with `"alg": "none"`, meaning tokens carry no cryptographic signature. A forged token with an arbitrary `sub` claim is accepted as fully authenticated. Additionally, the OTP endpoint enforces no attempt limits, making it trivially brute-forceable.

**Affected endpoint:**
```
POST /identity/api/auth/login
```

**Proof of concept — forged JWT header and payload:**
```json
{ "alg": "none" }
{ "sub": "victim@example.com", "role": "user" }
```

**Remediation:**
- Explicitly reject tokens where `alg` is `none`, regardless of case
- Whitelist accepted algorithms (e.g., `RS256` or `ES256`) and reject all others
- Enforce OTP attempt limits with progressive lockout after failed attempts

---

### 6. Missing Rate Limiting
**Severity:** High &nbsp;|&nbsp; **OWASP:** API4:2023

The application imposes no restrictions on request frequency. The community posts endpoint returns `200 OK` consistently across rapid repeated requests with no slowdown, blocking, or rate-limit headers present in the response.

**Affected endpoints:**
```
GET /community/api/v2/community/posts/recent
POST /workshop/api/merchant/contact_mechanic
```

**Remediation:**
- Implement rate limiting at the API gateway or middleware level (e.g., Nginx, AWS API Gateway)
- Add standard rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`)
- Apply per-user and per-IP quotas on all public-facing endpoints

---

### 7. Mass Assignment / Input Validation Failure
**Severity:** Critical &nbsp;|&nbsp; **OWASP:** API6:2023

The signup endpoint binds the entire request body directly to the user model without an allowlist. Injecting privileged fields such as `role`, `isAdmin`, and `accountType` into the registration request results in `200 OK` with those values persisted, granting the attacker self-assigned admin access.

**Affected endpoint:**
```
POST /identity/api/auth/signup
```

**Proof of concept — injected registration payload:**
```json
{
  "name": "attacker",
  "email": "attacker@example.com",
  "password": "password123",
  "number": "0700000000",
  "role": "ADMIN",
  "isAdmin": true,
  "accountType": "premium"
}
```

**Remediation:**
- Use a strict DTO (Data Transfer Object) pattern — accept only `name`, `email`, `password`, `number`
- Reject requests containing unexpected fields with `400 Bad Request`
- Never bind raw request bodies directly to internal model objects

---

## Methodology

The assessment followed a structured manual testing approach aligned with the OWASP API Security Testing Guide, divided into the following phases:

1. **Reconnaissance & Endpoint Discovery** — Passive observation of network traffic via browser DevTools and Burp Suite HTTP history to map the full API surface
2. **Authentication & Authorization Testing** — Testing for broken auth mechanisms, weak token generation, missing access controls, and privilege escalation
3. **Input Validation Testing** — Submitting unexpected parameters to identify mass assignment and improper input handling
4. **Rate Limiting & Resource Abuse** — Repeated request testing to identify missing throttling and brute force protections
5. **Information Disclosure Analysis** — Reviewing API responses for sensitive data leakage
6. **Documentation & Reporting** — Recording findings with screenshots, OWASP classification, severity scoring, and remediation guidance

---

## Scope

| Parameter | Details |
|---|---|
| **In Scope** | All API endpoints exposed by crAPI — identity, community, vehicle, workshop, and shop APIs |
| **Out of Scope** | Network infrastructure, operating system, third-party dependencies |
| **Assessment Style** | Black-box and grey-box (self-registered test account) |

---

## Disclaimer

This assessment was conducted solely against the OWASP crAPI intentionally vulnerable application in a controlled local Docker environment. No real systems, real user data, or production infrastructure were targeted. All findings are documented for educational and academic purposes only.

Unauthorized testing of real systems without explicit written permission is illegal and unethical.
