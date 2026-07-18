# Understanding SAML Direct Federation HAR Traces

## Table of Contents

- [Overview](#overview)
- [Direct Federation Authentication Flow](#direct-federation-authentication-flow)
- [How to Read a HAR Trace](#how-to-read-a-har-trace)
  - [What to Focus On](#what-to-focus-on)
  - [What to Ignore](#what-to-ignore)
- [Key Authentication Terms](#key-authentication-terms)
  - [SAMLRequest](#samlrequest)
  - [SAMLResponse](#samlresponse)
  - [RelayState](#relaystate)
- [Common Microsoft Entra ID URLs](#common-microsoft-entra-id-urls)
- [Common SAML Identity Provider URLs](#common-saml-identity-provider-urls)
  - [PingFederate](#pingfederate)
  - [ADFS](#adfs)
  - [Okta](#okta)
- [HAR Walkthrough Example](#har-walkthrough-example)
- [How to Determine Request Direction](#how-to-determine-request-direction)
- [Beginner's Guide: How to tell who sent what (Entra vs IdP)](#beginners-guide-how-to-tell-who-sent-what-entra-vs-idp)
  - [Quick checklist to determine direction](#quick-checklist-to-determine-direction)
  - [Concrete HAR examples (what you'll see in the HAR viewer)](#concrete-har-examples-what-youll-see-in-the-har-viewer)
  - [How to inspect these fields in common HAR viewers / devtools](#how-to-inspect-these-fields-in-common-har-viewers--devtools)
  - [Decoding SAML payloads (quick help)](#decoding-saml-payloads-quick-help)
  - [Tips to speed up HAR triage](#tips-to-speed-up-har-triage)
  - [Checklist: determining who initiated the SAML payload](#checklist-determining-who-initiated-the-saml-payload)
- [Direct Federation Troubleshooting Checklist](#direct-federation-troubleshooting-checklist)
- [Common Failure Patterns](#common-failure-patterns)
- [Mental Model for Reading HAR Traces](#mental-model-for-reading-har-traces)
- [Extra help for beginners — how to tell who sent the SAML message (Entra vs IdP)](#extra-help-for-beginners--how-to-tell-who-sent-the-saml-message-entra-vs-idp)
  - [1) Quick decision checklist (start here)](#1-quick-decision-checklist-start-here)
  - [2) Concrete, minimal HAR examples (what to look at in the Network panel)](#2-concrete-minimal-har-examples-what-to-look-at-in-the-network-panel)
  - [3) Fields to inspect in devtools / HAR viewer](#3-fields-to-inspect-in-devtools--har-viewer)
  - [4) How to decode SAML safely (inspect XML locally, redact before sharing)](#4-how-to-decode-saml-safely-inspect-xml-locally-redact-before-sharing)
  - [5) Helpful jq filters for big HARs (search HAR file for entries)](#5-helpful-jq-filters-for-big-hars-search-har-file-for-entries)
  - [6) Practical heuristics and red flags](#6-practical-heuristics-and-red-flags)
  - [7) What to capture when escalating](#7-what-to-capture-when-escalating)
  - [8) Pocket triage checklist (copyable)](#8-pocket-triage-checklist-copyable)
  - [9) Common beginner mistakes](#9-common-beginner-mistakes)

This document explains how to analyze HAR traces for Microsoft Entra ID Direct Federation scenarios involving external SAML Identity Providers (IdPs) such as:

- PingFederate
- ADFS
- Okta
- Custom SAML providers

The goal is to determine:

- Who initiated authentication
- Whether Entra ID redirected the user to the external IdP
- Whether the external IdP authenticated the user
- Whether the IdP returned a SAML assertion to Entra ID
- Whether Entra ID accepted or rejected the assertion
- Where the authentication flow failed

Most HAR traces contain hundreds of requests. In reality, only a few requests are relevant for authentication troubleshooting.

---

## Overview

Direct Federation is a configuration where Microsoft Entra ID delegates authentication of external users to a partner SAML IdP. Entra ID does not authenticate the external user's password; instead[...]

A successful flow looks like:

User -> Microsoft Entra ID -> External SAML IdP -> Microsoft Entra ID -> Application / Guest Redemption

---

## Direct Federation Authentication Flow

In Direct Federation, Microsoft Entra ID does **not** authenticate the external user's password. The steps are:

1. Entra ID sends a SAML Authentication Request to the partner IdP.
2. The partner IdP authenticates the user.
3. The partner IdP sends a signed SAML assertion (SAMLResponse) back to Entra ID.
4. Entra ID validates the assertion.
5. The user is redirected to guest redemption or the target application.

Diagram:

```text
User
 |
 v
Microsoft Entra ID (Resource Tenant)
 |
 | SAML AuthnRequest
 v
External SAML Identity Provider (Ping / ADFS / Okta)
 |
 | User Authentication
 v
External SAML Identity Provider
 |
 | SAMLResponse
 v
Microsoft Entra ID
 |
 v
Guest Redemption / Application Access
```

---

## How to Read a HAR Trace

Do NOT read every request sequentially. Instead, filter and focus on the requests relevant to the federation flow.

### What to Focus On

- Redirects (302, 303, 307)
- Requests or parameters that include `SAMLRequest` or `SAMLResponse`
- `RelayState` values and where they travel
- Requests to `login.microsoftonline.com`, `aadcdn.msftauth.net`, and other Entra endpoints
- Requests to the external IdP endpoints (Ping, ADFS, Okta, etc.)

### What to Ignore

Ignore page-rendering assets that are not part of the authentication handshake:

```text
.css
.js
.png
.jpg
.jpeg
.svg
.woff
favicon.ico
```

Examples of noise:

```text
main.css
jquery.js
bootstrap.js
login.js
logo.png
background.jpg
```

These are usually page assets and not part of the authentication flow.

---

## Key Authentication Terms

### SAMLRequest

A SAML Authentication Request generated by Entra ID and sent to the external IdP.

Example parameter (in a request URL or POST body):

```text
SAMLRequest=
```

Meaning:

```text
Entra ID → Please authenticate this user.
```

### SAMLResponse

A signed SAML assertion returned by the external IdP after authentication.

Example parameter:

```text
SAMLResponse=
```

Meaning:

```text
External IdP → User authenticated successfully. (Signed assertion attached.)
```

### RelayState

A state-tracking value used throughout the federation transaction.

Example:

```text
RelayState=xyz123
```

RelayState commonly contains:

- Tenant context
- Application context
- Redirect information
- Session/federation transaction state

Important: If Entra sends a SAMLRequest with `RelayState=abc123`, the external IdP must return the SAMLResponse with the identical `RelayState=abc123`. Failure to preserve RelayState can cause En[...]

---

## Common Microsoft Entra ID URLs

When reviewing a HAR trace, these hostnames indicate Entra ID involvement:

```text
login.microsoftonline.com
aadcdn.msftauth.net
login.live.com
```

A common federation endpoint is:

```text
https://login.microsoftonline.com/login.srf
```

Example:

```text
POST https://login.microsoftonline.com/login.srf
```

This usually means the external IdP sent a `SAMLResponse` to Entra ID and Entra ID is processing the assertion.

---

## Common SAML Identity Provider URLs

### PingFederate

Common endpoints:

```text
/startSSO.ping
/resumeSAML20/idp/startSSO.ping
```

Example:

```text
https://secureaccess.company.com/idp/startSSO.ping
```

### ADFS

Common endpoints:

```text
/adfs/ls/
/adfs/portal/
```

### Okta

Okta may use endpoints under the customer domain or org-specific paths. Look for requests to the Okta org domain and SAML endpoints.

---

## HAR Walkthrough Example

(Include a short, focused example HAR walk-through here. For real troubleshooting, extract only the requests that show `SAMLRequest`, IdP redirects, the `SAMLResponse` POST back to Entra ID, and [...]

Example sequence to extract from a HAR:

1. Request to Entra that initiates federation and returns a redirect to the IdP (contains `SAMLRequest`).
2. Redirect to IdP startSSO endpoint.
3. IdP login and authentication requests.
4. POST from IdP to `https://login.microsoftonline.com/login.srf` (contains `SAMLResponse` and `RelayState`).
5. Entra processes response and redirects to guest redemption or the target app.

---

## How to Determine Request Direction

When reading a HAR, you need to know which side sent each SAML payload:

- SAMLRequest originates from Entra ID and is sent to the IdP.
- SAMLResponse originates from the IdP and is sent back to Entra ID.
- RelayState should travel with the SAML payload and be preserved.

Look at the request hostnames and HTTP methods: a POST to `login.srf` that includes `SAMLResponse` is the IdP returning the assertion to Entra ID.


---

## Beginner's Guide: How to tell who sent what (Entra vs IdP)

If you're new to HARs, the subtle part is *who created* each SAML payload and *who it's being sent to*. These quick checks and examples will make that decision straightforward.

### Quick checklist to determine direction

1. Identify the request that carries `SAMLRequest` or `SAMLResponse`.
2. Check the request hostname (the `Host` / request URL):
   - If the request target is an IdP hostname (e.g., `secureaccess.company.com`, `idp.example.com`, Okta org domain, `/adfs/ls`), the browser is contacting the IdP.
   - If the request target is `login.microsoftonline.com` (or `login.srf`), the browser is posting the SAMLResponse back to Entra ID.
3. Check the HTTP method:
   - A GET with `SAMLRequest=` in the query string usually indicates an HTTP-Redirect binding (Entra or the app issued a redirect to the IdP).
   - A POST with `SAMLRequest` in form data means the browser is posting the SAMLRequest to the IdP (HTTP-POST binding).
   - A POST with `SAMLResponse` in form data to `login.srf` indicates the IdP returned a SAML assertion to Entra.
4. Inspect the response that caused the browser to make the request:
   - Look for a 302/303 response from an Entra-hosted URL that contains a `Location:` header pointing to an IdP with `SAMLRequest=` — that shows Entra issued the redirect.
   - If you see a 200 response from an IdP login page followed by a POST to `login.srf`, the IdP authenticated the user and posted the assertion back.

### Concrete HAR examples (what you'll see in the HAR viewer)

- Example A — Entra issues redirect to IdP (HTTP-Redirect binding):

  - Response (from `login.microsoftonline.com`): 302 Location: `https://idp.example.com/idp/startSSO?p=SAMLRequest=...&RelayState=abc123`
  - In HAR: the Entra response has a `Location` header with an IdP URL that contains `SAMLRequest=`. This proves Entra started the flow and redirected the browser to the IdP.

- Example B — Browser posts SAMLRequest to IdP (HTTP-POST binding):

  - Request: POST `https://idp.example.com/idp/profile/SAML2/POST/SSO`
  - Request body (form data): `SAMLRequest=...` `RelayState=abc123`
  - In HAR: check the request -> Form Data section. If `SAMLRequest` is present there, the browser is posting to the IdP.

- Example C — IdP posts SAMLResponse back to Entra:

  - Request: POST `https://login.microsoftonline.com/login.srf`
  - Request body: `SAMLResponse=...` `RelayState=abc123`
  - In HAR: the POST target is `login.srf` and the form data includes `SAMLResponse` — this is the IdP returning the assertion to Entra.

### How to inspect these fields in common HAR viewers / devtools

- Chrome / Edge DevTools: Network tab -> find the request -> click -> Headers shows Request URL and Response headers; under "Payload" or "Form Data" you'll see `SAMLRequest`/`SAMLResponse`/`Relay[...]
- Firefox: Network tab -> click request -> "Request" -> "Post" or "Query" sections show form/query parameters.
- If you have a .har file, load it in the browser's devtools or use an online HAR viewer and inspect the request's querystring / postData.text.

### Decoding SAML payloads (quick help)

SAMLRequest and SAMLResponse are base64-encoded. They may also be DEFLATE-compressed (HTTP-Redirect binding) before base64. To inspect the XML:

- Quick Python one-liner (POST binding usually base64-encoded XML):

```python
# decode base64 SAMLResponse (no deflate)
import base64
print(base64.b64decode("<paste-base64-here>").decode('utf-8'))
```

- If the SAML is deflated (redirect binding) you may need to inflate first:

```python
import base64, zlib
data = base64.b64decode("<paste-base64-here>")
xml = zlib.decompress(data, -15)  # -15 window to omit zlib headers
print(xml.decode('utf-8'))
```

Safety: never paste production tokens or user identifiers into public tools. Redact or run decoding locally.

### Tips to speed up HAR triage

- Filter the HAR list by `SAMLRequest`, `SAMLResponse`, `RelayState`, or by hostname `login.microsoftonline.com` or the IdP host.
- Look for the first redirect away from Entra's hostname — that's usually the point Entra handed control to the IdP.
- Use the request timestamps to follow the sequence: Entra -> (redirect) -> IdP login -> (POST) -> Entra.
- When in doubt, follow the `RelayState` value: it starts with Entra's SAMLRequest and should be returned exactly with the SAMLResponse.

### Checklist: determining who initiated the SAML payload

- If the SAML payload appears as a query string parameter in a Location header on a response from an Entra URL: Entra created the request and redirected the browser.
- If the SAML payload appears in the request body (Form Data) of a POST to `login.srf`: the IdP posted the assertion back to Entra.
- If you see a POST to an IdP endpoint with `SAMLRequest` in Form Data: the browser is delivering Entra's SAMLRequest to the IdP.

---

## Direct Federation Troubleshooting Checklist

1. Find the `SAMLRequest` (Entra → IdP). Confirm it exists.
2. Confirm the browser was redirected to the IdP endpoint.
3. Confirm the user authenticated at the IdP (IdP response pages, or 200s on login endpoints).
4. Find the `SAMLResponse` POST to Entra (`login.srf`).
5. Confirm `RelayState` in the response matches the original value.
6. Inspect Entra's response to the `SAMLResponse` POST (200 or redirect to app). Look for error messages or status codes.
7. If Entra rejects the assertion, capture any error text or response codes returned.

---

## Common Failure Patterns

- Missing or altered RelayState
- Signed assertion validation failures (clock skew, certificate mismatch)
- Incorrect audience or recipient values in the assertion
- IdP returning an error HTML page instead of a `SAMLResponse`
- Network redirects that drop POST bodies

---

## Mental Model for Reading HAR Traces

- Ignore noise (assets) and focus on federated requests.
- Map the flow: Entra -> IdP (SAMLRequest) then IdP -> Entra (SAMLResponse).
- Use hostnames and request methods to determine direction.
- Preserve exact `RelayState` values when tracing the transaction.

---

## Extra help for beginners — how to tell who sent the SAML message (Entra vs IdP)

Problem most people see: HARs are noisy and it's not obvious whether Entra ID initiated a redirect or the external IdP sent a SAMLRequest / SAMLResponse. Use the checks below to decide reliably.

### 1) Quick decision checklist (start here)

- Find the request that contains SAMLRequest or SAMLResponse (query string or form data).
- Check the Request URL / Host:
  - IdP host (e.g., idp.example.com, secureaccess.company.com, customer-okta-domain, or paths like /adfs/ls/) → browser is contacting the IdP.
  - login.microsoftonline.com (often POST to /login.srf) → browser is posting back to Entra ID.
- Check HTTP method and where the SAML parameter is:
  - GET (or Location header with SAMLRequest in the query) → HTTP-Redirect binding (redirection).
  - POST with SAMLRequest in form data to an IdP endpoint → browser delivered Entra's SAMLRequest to the IdP (HTTP-POST binding).
  - POST with SAMLResponse in form data to login.srf → IdP posted the assertion to Entra ID.
- Check RelayState: the same value must travel with the SAMLRequest and SAMLResponse — use it to link the two.

### 2) Concrete, minimal HAR examples (what to look at in the Network panel)

- Entra issued redirect (HTTP-Redirect)
  - Response: status 302 from login.microsoftonline.com
  - Response header: Location: https://idp.example.com/idp/startSSO?SAMLRequest=...&RelayState=abc123
  - Interpretation: Entra created the SAMLRequest and redirected the browser to the IdP.

- Browser posts SAMLRequest to IdP (HTTP-POST)
  - Request: POST https://idp.example.com/idp/SAML2/POST/SSO
  - Form data: SAMLRequest=<base64...> ; RelayState=abc123
  - Interpretation: Browser is sending Entra's SAMLRequest to the IdP.

- IdP posts SAMLResponse back to Entra
  - Request: POST https://login.microsoftonline.com/login.srf
  - Form data: SAMLResponse=<base64...> ; RelayState=abc123
  - Interpretation: IdP returned the assertion to Entra.

### 3) Fields to inspect in devtools / HAR viewer

- Request URL and Hostname (top line).
- HTTP method (GET vs POST).
- Response status (302 with Location means redirect).
- Response headers — look for Location containing SAMLRequest.
- Request payload / Form Data — look for SAMLRequest/SAMLResponse/RelayState.
- Initiator and timing columns — to reconstruct sequence.
- Response body (if Entra returns an HTML error after SAMLResponse, it may include a human-readable reason).

### 4) How to decode SAML safely (inspect XML locally, redact before sharing)

- POST binding: SAMLRequest / SAMLResponse are base64-encoded XML.
  - Python decode (POST binding):
    ```python
    import base64
    xml = base64.b64decode("BASE64_HERE").decode('utf-8')
    print(xml)
    ```
- Redirect binding: SAML is often DEFLATE-compressed then base64-encoded and URL-encoded.
  - Python decode (redirect binding):
    ```python
    import base64, zlib
    data = base64.b64decode("BASE64_HERE")
    xml = zlib.decompress(data, -15)   # -15 window to omit zlib headers
    print(xml.decode('utf-8'))
    ```
- Key XML nodes to examine (once decoded):
  - <Issuer> — who issued the message (SAMLRequest Issuer = requester; SAMLResponse Issuer = IdP).
  - SAMLResponse: check Issuer, Subject/NameID, Audience (and AudienceRestriction), Destination/Recipient (should be Entra's login.srf), Conditions (NotBefore/NotOnOrAfter).
  - Signature: presence of a valid Signature element and, if possible, matching cert in IdP config.

### 5) Helpful jq filters for big HARs (search HAR file for entries)

- Find POSTs containing SAMLResponse:
  jq:
  ```bash
  jq '.log.entries[] | select(.request.postData.text // "" | test("SAMLResponse")) | {url:.request.url, time:.startedDateTime}' big.har
  ```
- Find responses with Location that contain SAMLRequest:
  jq:
  ```bash
  jq '.log.entries[] | select(.response.headers[]?; .name=="Location" and (.value|test("SAMLRequest"))) | {from:.request.url, location:(.response.headers[]|select(.name=="Location").value)}' big.har
  ```

### 6) Practical heuristics and red flags

- First redirect away from an Entra hostname → likely Entra handed off to IdP.
- POST to login.srf with SAMLResponse → IdP returned an assertion to Entra.
- No SAMLResponse POST to login.srf after IdP login → IdP likely failed or returned an HTML error instead of SAMLResponse.
- Entra receives SAMLResponse but responds with an error page → assertion rejected; look for error text and check:
  - RelayState mismatch
  - Audience/Recipient mismatch
  - Signature/certificate issues
  - Clock skew (NotBefore/NotOnOrAfter)

### 7) What to capture when escalating

- Minimal relevant HAR snippet (redacted): the Entra redirect (response with Location and SAMLRequest) OR the POST that delivered SAMLRequest to IdP; the IdP login POSTs and the POST to login.srf with SAMLResponse.
- Decoded, redacted SAMLResponse XML (remove NameID, emails, or other PII; remove certificate blocks if needed).
- Timestamps (client time and system time) to check clock skew.
- IdP logs around the same timestamps (if available).

### 8) Pocket triage checklist (copyable)

- Locate SAMLRequest or SAMLResponse.
- If SAMLRequest appears in a Location header from login.microsoftonline.com → Entra initiated the redirect.
- If SAMLRequest appears in POST Form Data to an IdP → browser delivered Entra's request to IdP.
- If SAMLResponse appears in POST Form Data to login.srf → IdP posted assertion to Entra.
- Verify RelayState matches between request and response.
- If assertion reached Entra and Entra returned an error, copy Entra's response body for clues.

### 9) Common beginner mistakes

- Treating GET and POST the same — GET is usually redirect (SAML in query), POST is form submission (SAML in body).
- Not following RelayState — it's the easiest way to tie the two sides of the transaction together.
- Sharing raw SAML without redacting — decode locally and redact before sharing.

---

If you'd like, I can:

- Add a concrete, redacted HAR example with request/response snippets and decoded XML.
- Add IdP-specific troubleshooting examples for PingFederate, ADFS, and Okta.
