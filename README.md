

## Extra help for beginners — how to tell who sent the SAML message (Entra vs IdP)

Problem most people see: HARs are noisy and it's not obvious whether Entra ID initiated a redirect or the external IdP sent a SAMLRequest / SAMLResponse. Use the checks below to decide reliably.

1) Quick decision checklist (start here)
- Find the request that contains SAMLRequest or SAMLResponse (query string or form data).
- Check the Request URL / Host:
  - IdP host (e.g., idp.example.com, secureaccess.company.com, customer-okta-domain, or paths like /adfs/ls/) → browser is contacting the IdP.
  - login.microsoftonline.com (often POST to /login.srf) → browser is posting back to Entra ID.
- Check HTTP method and where the SAML parameter is:
  - GET (or Location header with SAMLRequest in the query) → HTTP-Redirect binding (redirection).
  - POST with SAMLRequest in form data to an IdP endpoint → browser delivered Entra’s SAMLRequest to the IdP (HTTP-POST binding).
  - POST with SAMLResponse in form data to login.srf → IdP posted the assertion to Entra ID.
- Check RelayState: the same value must travel with the SAMLRequest and SAMLResponse — use it to link the two.

2) Concrete, minimal HAR examples (what to look at in the Network panel)
- Entra issued redirect (HTTP-Redirect)
  - Response: status 302 from login.microsoftonline.com
  - Response header: Location: https://idp.example.com/idp/startSSO?SAMLRequest=...&RelayState=abc123
  - Interpretation: Entra created the SAMLRequest and redirected the browser to the IdP.

- Browser posts SAMLRequest to IdP (HTTP-POST)
  - Request: POST https://idp.example.com/idp/SAML2/POST/SSO
  - Form data: SAMLRequest=<base64...> ; RelayState=abc123
  - Interpretation: Browser is sending Entra’s SAMLRequest to the IdP.

- IdP posts SAMLResponse back to Entra
  - Request: POST https://login.microsoftonline.com/login.srf
  - Form data: SAMLResponse=<base64...> ; RelayState=abc123
  - Interpretation: IdP returned the assertion to Entra.

3) Fields to inspect in devtools / HAR viewer
- Request URL and Hostname (top line).
- HTTP method (GET vs POST).
- Response status (302 with Location means redirect).
- Response headers — look for Location containing SAMLRequest.
- Request payload / Form Data — look for SAMLRequest/SAMLResponse/RelayState.
- Initiator and timing columns — to reconstruct sequence.
- Response body (if Entra returns an HTML error after SAMLResponse, it may include a human-readable reason).

4) How to decode SAML safely (inspect XML locally, redact before sharing)
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

5) Helpful jq filters for big HARs (search HAR file for entries)
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

6) Practical heuristics and red flags
- First redirect away from an Entra hostname → likely Entra handed off to IdP.
- POST to login.srf with SAMLResponse → IdP returned an assertion to Entra.
- No SAMLResponse POST to login.srf after IdP login → IdP likely failed or returned an HTML error instead of SAMLResponse.
- Entra receives SAMLResponse but responds with an error page → assertion rejected; look for error text and check:
  - RelayState mismatch
  - Audience/Recipient mismatch
  - Signature/certificate issues
  - Clock skew (NotBefore/NotOnOrAfter)

7) What to capture when escalating
- Minimal relevant HAR snippet (redacted): the Entra redirect (response with Location and SAMLRequest) OR the POST that delivered SAMLRequest to IdP; the IdP login POSTs and the POST to login.srf that carries SAMLResponse; Entra’s response to that POST.
- Decoded, redacted SAMLResponse XML (remove NameID, emails, or other PII; remove certificate blocks if needed).
- Timestamps (client time and system time) to check clock skew.
- IdP logs around the same timestamps (if available).

8) Pocket triage checklist (copyable)
- Locate SAMLRequest or SAMLResponse.
- If SAMLRequest appears in a Location header from login.microsoftonline.com → Entra initiated the redirect.
- If SAMLRequest appears in POST Form Data to an IdP → browser delivered Entra’s request to IdP.
- If SAMLResponse appears in POST Form Data to login.srf → IdP posted assertion to Entra.
- Verify RelayState matches between request and response.
- If assertion reached Entra and Entra returned an error, copy Entra’s response body for clues.

9) Common beginner mistakes
- Treating GET and POST the same — GET is usually redirect (SAML in query), POST is form submission (SAML in body).
- Not following RelayState — it’s the easiest way to tie the two sides of the transaction together.
- Sharing raw SAML without redacting — decode locally and redact before sharing.

