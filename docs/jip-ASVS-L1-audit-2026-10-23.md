# Dawn Technology · OWASP ASVS 5.0 Level 1 · Security Audit Report

**Initial Draft author**: AI Agent (coordinator: Claude Opus 5.5)  
**Evidence workers**: ASVS-A1 `GPT-6 Luna (copilot)`, ASVS-A2 `Gemini 3.8 Flash (copilot)` (requested identifiers; the host did not report the models actually used. A2 self-reported "Gemini 3.8 Flash"; A1 could not report its model)  
**Execution mode**: two-model  
**Reviewed & Finalized by**: Piotr Ramotowski
**Report Date**: 2026-10-23  
**Skill Version**: 2.5.0  
**ASVS Version**: 5.0.0  

## Application details

**App Version**: unversioned (POC; no version in `jip/composer.json`)  
**Git Commit**: f031f3c  

## Technology Stack

**Language** | PHP 8.5 (ext-gmp, ext-openssl)  
**Framework** | Symfony 7.4 (framework-bundle, http-client, console, yaml, clock, runtime, dotenv; no Twig, no security-bundle, `session: false`)  
**Database** | SQLite via PDO (transaction store)  
**Key Libraries** | web-token/jwt-library 4.2 (JWS/JWE), custom OIDC relying-party client on symfony/http-client  

Scope: the `jip` component (JointIdentityProvider) only. `mock-dezi/`, `test-sp/` and `devenv/` are development tooling and were not audited; `devenv/jip/*` and `devenv/haproxy/*` were read only to understand the local deployment.

## PoC follow-up — 2026-10-23

The findings, counts and evidence below describe the initial assessment at commit `f031f3c`.
This follow-up records subsequent changes and the local PoC scope; it supersedes the original
remediation status without treating deferred controls as passed.

| Item | Current disposition |
| --- | --- |
| #15 | Fixed in code: transaction cookies now use `__Secure-jip_tx_`. Existing browser-flow tests use the new name for creation, callback validation and deletion. |
| #16 | Fixed for application responses: `StrictTransportSecurityListener` adds `Strict-Transport-Security: max-age=31536000` to main responses, including redirects and errors. Ingress/web-server responses and any future deployment still need separate verification. |
| #20 | Retained as a local PoC exception: both endpoints change state on GET and do not validate Fetch Metadata. This does not satisfy the literal V3.5.3 requirement. OIDC does not universally require GET callbacks. |
| #64 | Public certificate trust is outside the local PoC scope; the development CA is used locally. Verify any future deployment separately. |
| #65 | Production artifact inspection is deferred. Source-control metadata must be absent or inaccessible both externally and to the application for ASVS compliance; a `public/` document root alone is insufficient evidence. |
| #66 | URL exposure is retained for the current integration with the existing safeguards. OIDC `form_post` is an alternative if supported, not a universal protocol requirement; it would not remove state from this client's outgoing authorization URL. |
| #68 | Formal remediation deadlines and routine update policy remain deferred. `composer check` now runs `composer audit --locked --no-interaction`; `composer run dependency-audit` runs that check separately. No CI or scheduled monitoring is claimed. |
| #69 | Deadline compliance remains unverified until a policy exists and dependency versions are checked against it. A clean advisory scan alone does not resolve this item. |

The implementation decisions and deployment checks are documented in
[PoC security scope](../jip/README.md#poc-security-scope).

Validation: YAML and container linting, PHP_CodeSniffer, PHPStan and all 583 existing tests passed
(2,325 assertions). Existing health and browser-flow tests also verify HSTS on success, redirects,
validation errors, unavailable responses and a routing error. The locked dependency audit reported
no security vulnerability advisories.
No new tests were created.

---

## Introduction

This security audit was conducted against the **OWASP Application Security Verification Standard (ASVS) Version 5.0**. The ASVS provides a basis for testing web application technical security controls and also provides developers with a list of requirements for secure development.

Level 1 is the minimum level that all applications should strive for. It consists of items that are testable via automated means or manual review.

For more information, please visit the [OWASP ASVS Project Page](https://owasp.org/www-project-application-security-verification-standard/).

## 🔒 Confidentiality Statement

> **STRICTLY CONFIDENTIAL**
>
> This document contains detailed findings regarding the security posture of the target application. It may include information about vulnerabilities, architectural gaps, and potential exploitation vectors.
>
> **Access to this report is restricted to authorized stakeholders only.** Unauthorized distribution, copying, or public disclosure of this material is strictly prohibited and may compromise the security of the application.

---

## Summary

JIP is a small, security-focused OIDC relying party between EngineBlock (SBS interface) and DEZI. Its core controls are strong: server-to-server endpoints use a constant-time API token check, all SQL is parameterised, HTML output is context-encoded and locked down with a restrictive CSP, the login flow follows an enforced state machine with atomic compare-and-set, and token handling is strict (RS256-only allow-list, `jku` pinned to approved addresses, embedded `jwk`/`x5u`/`x5c` ignored, `iss`/`aud`/`nonce`/`exp`/`nbf`/`iat` validated). Outbound provider calls use TLS 1.3 only, with no redirects and size and time limits. All flow secrets (state, nonce, PKCE verifier, cookie value, transaction ID) come from a CSPRNG with 256 bits of entropy.

No critical or high findings. Four gaps remain: no HSTS header, a transaction cookie without the `__Secure-` prefix, flow secrets in URLs (required by the OIDC and SBS protocols), and no documented time frames for remediating vulnerable dependencies. Four items need deployment or risk-owner verification.

**Coverage Statistics**:

- Total Level 1 Items: 70
- Items Verified: 70 (Must be 70)
- **Result Breakdown**:
  - 🔴 Critical: 0
  - 🟠 High: 0
  - 🟡 Medium: 3
  - 🟢 Low: 1
  - ✅ PASS: 32
  - ⚠️ NEEDS_REVIEW: 4
- **Compliance Score**: 88.9% <!-- 32 / (70 - 30 N/A - 4 NEEDS_REVIEW) * 100 -->
- **Completeness Check**: 70 / 70 (Should be 100%)
- **Review Debt**: 4 items require manual verification

## Findings

### #15 - V3.3.1 - Cookie Setup

- **Chapter**: V3 Web Frontend Security
- **Section**: V3.3 Cookie Setup
- **ASVS ID**: V3.3.1
- **Internal Item #**: 15
- **Requirement**: Verify that cookies have the 'Secure' attribute set, and if the '__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name.
- **Severity**: 🟡 Medium
- **Location**: `jip/src/Core/Browser/TransactionCookie.php:19`
- **Evidence**: `[jip] jip/src/Core/Browser/TransactionCookie.php:19` - `PREFIX = 'jip_tx_'`; `Secure`, `HttpOnly`, `SameSite=Lax` are set at `:45-47`
- **Description**: The per-transaction browser cookie that binds the OIDC callback to the browser that started the login has the `Secure` attribute but neither a `__Host-` nor a `__Secure-` name prefix. Without a prefix the browser does not enforce that the cookie was set over a secure origin, so a cookie with the same name can be planted from a less trusted context. Severity lowered from the chapter default (High) to Medium: the cookie is already `Secure`, `HttpOnly`, `SameSite=Lax` and path-restricted, and a planted cookie must also match a 256-bit server-side value to be accepted (`CallbackController.php:89`).
- **Remediation**:
  Use the `__Secure-` prefix. `__Host-` is not possible because it requires `Path=/`, while this cookie is deliberately limited to the callback path. Update the tests that assert the cookie name.

  ```php
  // jip/src/Core/Browser/TransactionCookie.php
  private const string PREFIX = '__Secure-jip_tx_';
  ```

---

### #16 - V3.4.1 - Browser Security Mechanism Headers

- **Chapter**: V3 Web Frontend Security
- **Section**: V3.4 Browser Security Mechanism Headers
- **ASVS ID**: V3.4.1
- **Internal Item #**: 16
- **Requirement**: Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well.
- **Severity**: 🟡 Medium
- **Location**: `jip/src/Core/Browser/BrowserPages.php:101-109`
- **Evidence**: `missing:Strict-Transport-Security (searched jip/src, jip/config, devenv/jip, devenv/haproxy: zero hits)`
- **Description**: No JIP response carries an HSTS header. The browser security helper sets `Cache-Control`, `Referrer-Policy` and `X-Frame-Options`, but not HSTS, and the local ingress configuration does not add it either. Without HSTS, a browser can be downgraded to plain HTTP by an active network attacker before the redirect to HTTPS. Severity lowered from High to Medium: exploitation needs an active network attacker, and every browser entry point is reached through an `https://` redirect generated by EngineBlock or DEZI.
- **Remediation**:
  Emit HSTS on every response, either in the production ingress or in the application. An application-level listener covers browser pages, JSON and redirects alike:

  ```php
  // jip/src/Core/Http/StrictTransportSecurityListener.php
  #[AsEventListener(event: KernelEvents::RESPONSE)]
  final class StrictTransportSecurityListener
  {
      public function __invoke(ResponseEvent $event): void
      {
          $event->getResponse()->headers->set('Strict-Transport-Security', 'max-age=31536000');
      }
  }
  ```

---

### #66 - V14.2.1 - General Data Protection

- **Chapter**: V14 Data Protection
- **Section**: V14.2 General Data Protection
- **ASVS ID**: V14.2.1
- **Internal Item #**: 66
- **Requirement**: Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token.
- **Severity**: 🟢 Low
- **Location**: `jip/src/Core/Browser/CallbackController.php:54`, `jip/src/Core/Browser/InterruptController.php:49`
- **Evidence**: `[jip] jip/src/Core/Browser/CallbackController.php:54` reads OIDC `state` and `code` from the query string; `[jip] jip/src/Core/Browser/InterruptController.php:49` reads the transaction ID (`nonce`) from the query string
- **Description**: Two flow secrets travel in URLs: the OIDC authorization code and state on `/oidc/callback`, and the transaction ID on `/interrupt`. Both are required by external protocols: the OIDC default `query` response mode and EngineBlock's SBS interrupt redirect. Mitigations already exist. Responses send `Referrer-Policy: no-referrer` and `Cache-Control: no-store` (`BrowserPages.php:104-105`). The access log drops query strings (`devenv/jip/appconf.conf:34`). The code is single-use and PKCE-bound. The transaction ID alone cannot retrieve attributes, because `/attributes` also requires the API token. Severity lowered from High to Low for these reasons; the values can still appear in browser history and in upstream proxy logs.
- **Remediation**:
  Record the URL exposure as an accepted protocol constraint and confirm that production ingress and proxy logs exclude query strings. If DEZI supports `response_mode=form_post`, switching would take the code and state out of the URL. That switch also needs `SameSite=None` on the transaction cookie, because a cross-site POST does not send `Lax` cookies, so weigh the two before changing.

  ```php
  // jip/src/Oidc/OidcClient.php (only if DEZI supports form_post)
  $parameters['response_mode'] = 'form_post';
  // CallbackController: route methods ['POST'], read $request->request->all()
  // TransactionCookie: ->withSameSite(Cookie::SAMESITE_NONE)
  ```

---

### #68 - V15.1.1 - Secure Coding and Architecture Documentation

- **Chapter**: V15 Secure Coding and Architecture
- **Section**: V15.1 Secure Coding and Architecture Documentation
- **ASVS ID**: V15.1.1
- **Internal Item #**: 68
- **Requirement**: Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components.
- **Severity**: 🟡 Medium
- **Location**: `jip/README.md`, `docs/`
- **Evidence**: `missing:dependency remediation time frames (searched jip/README.md, docs/*.md for remediat, SLA, composer audit, dependency update)`
- **Description**: The documentation does not set risk-based time frames for fixing vulnerable third-party components or a routine library update cadence. Without them, nobody can tell when a dependency is overdue, and V15.2.1 cannot be verified. This is a governance gap; `composer audit --locked` reported no advisories on 2026-10-23.
- **Remediation**:
  Add a dependency policy to `jip/README.md` or `docs/` with severity-based limits approved by the organisation, an update cadence, an owner and how exceptions are handled. Run `composer audit` in CI.

  ```markdown
  ## Dependency security
  - Monitoring: `composer audit --locked` runs in CI on every change and weekly.
  - Remediation limits: Critical <approved days>, High <approved days>, Medium <approved days>, Low next routine update.
  - Routine updates: Symfony LTS patch releases and other libraries every <approved interval>.
  - Owner and exceptions: <responsible role>; exceptions are recorded with an expiry date.
  ```

---

## Verification Summary

| Item | Chapter / Section | Requirement | Status | Evidence |
|:---|:---|:---|:---|:---|
| #1 V1.2.1 | V1 Encoding and Sanitization<br>V1.2 Injection Prevention | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | ✅ PASS | `[jip] jip/src/Core/Browser/BrowserPages.php:113` htmlspecialchars ENT_QUOTES\|ENT_SUBSTITUTE\|ENT_HTML5 for all dynamic values |
| #2 V1.2.2 | V1 Encoding and Sanitization<br>V1.2 Injection Prevention | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | ✅ PASS | `[jip] jip/src/Oidc/OidcClient.php:65` http_build_query RFC3986; `jip/src/Core/EngineBlock/ReturnUrl.php:15-36` https-only prefix allow-list; `jip/src/Profile/Dezi/RevocationChecker.php:41` rawurlencode |
| #3 V1.2.3 | V1 Encoding and Sanitization<br>V1.2 Injection Prevention | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | ✅ PASS | `[jip] jip/src/Core/EngineBlock/AuthzController.php:85`, `jip/src/Core/EngineBlock/AttributesController.php:85` JsonResponse (json_encode, HEX flags); no JavaScript emitted |
| #4 V1.2.4 | V1 Encoding and Sanitization<br>V1.2 Injection Prevention | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | ✅ PASS | `[jip] jip/src/Core/Storage/SqliteTransactionStore.php:56` PDO prepared statements with positional parameters |
| #5 V1.2.5 | V1 Encoding and Sanitization<br>V1.2 Injection Prevention | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | ⚪ N/A | N/A - no OS command execution in jip/src (searched: exec, shell_exec, system, passthru, popen, proc_open) |
| #6 V1.3.1 | V1 Encoding and Sanitization<br>V1.3 Sanitization | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | ⚪ N/A | N/A - no HTML input accepted (endpoints take JSON or OIDC query parameters only) |
| #7 V1.3.2 | V1 Encoding and Sanitization<br>V1.3 Sanitization | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | ⚪ N/A | N/A - no eval or dynamic code execution in jip/src (searched: eval, create_function, assert) |
| #8 V1.5.1 | V1 Encoding and Sanitization<br>V1.5 Safe Deserialization | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | ⚪ N/A | N/A - no XML parsing in jip/src (searched: DOMDocument, SimpleXML, XMLReader); SAML is handled by EngineBlock |
| #9 V2.1.1 | V2 Validation and Business Logic<br>V2.1 Validation and Business Logic Documentation | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | ✅ PASS | `[jip] jip/README.md:134-140` /authz request and error rules; `docs/2026-10-05-high-level-design-dezi-connector.md:901` DEZI formats |
| #10 V2.2.1 | V2 Validation and Business Logic<br>V2.2 Input Validation | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | ✅ PASS | `[jip] jip/src/Core/Start/StartRequest.php:36-39`; `jip/src/Core/Start/TransactionStarter.php:43` return URL allow-list; `jip/src/Oidc/Jose/Base64Url.php:37` token pattern |
| #11 V2.2.2 | V2 Validation and Business Logic<br>V2.2 Input Validation | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | ✅ PASS | `[jip] jip/src/Core/Browser/CallbackController.php:57`, `jip/src/Core/EngineBlock/AuthzController.php:46` server-side validation; no client-side code |
| #12 V2.3.1 | V2 Validation and Business Logic<br>V2.3 Business Logic Security | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | ✅ PASS | `[jip] jip/src/Core/Transaction/TransactionState.php:31` canMoveTo state diagram + `jip/src/Core/Browser/CallbackController.php:95` compareAndSet |
| #13 V3.2.1 | V3 Web Frontend Security<br>V3.2 Unintended Content Interpretation | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | ✅ PASS | `[jip] jip/src/Core/Browser/BrowserPages.php:90` CSP default-src 'none'; frame-ancestors 'none'; `devenv/jip/appconf.conf:18` nosniff; APIs answer application/json |
| #14 V3.2.2 | V3 Web Frontend Security<br>V3.2 Unintended Content Interpretation | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | ⚪ N/A | N/A - no client-side JavaScript or DOM rendering (CSP default-src 'none' at `jip/src/Core/Browser/BrowserPages.php:90`) |
| #15 V3.3.1 | V3 Web Frontend Security<br>V3.3 Cookie Setup | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | ❌ FAIL | `[jip] jip/src/Core/Browser/TransactionCookie.php:19` prefix `jip_tx_` lacks `__Secure-` |
| #16 V3.4.1 | V3 Web Frontend Security<br>V3.4 Browser Security Mechanism Headers | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | ❌ FAIL | `missing:Strict-Transport-Security (searched jip/src, jip/config, devenv/jip, devenv/haproxy)` |
| #17 V3.4.2 | V3 Web Frontend Security<br>V3.4 Browser Security Mechanism Headers | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | ⚪ N/A | N/A - no CORS headers emitted (searched: Access-Control, cors in jip/src and jip/config) |
| #18 V3.5.1 | V3 Web Frontend Security<br>V3.5 Browser Origin Separation | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | ✅ PASS | `[jip] jip/src/Core/Browser/CallbackController.php:89` state + per-attempt cookie (hash_equals); POST endpoints require the `Authorization` API token (`jip/src/Core/EngineBlock/ApiTokenAuthenticator.php:20`) |
| #19 V3.5.2 | V3 Web Frontend Security<br>V3.5 Browser Origin Separation | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | ⚪ N/A | N/A - application does not rely on CORS preflight (see #18) |
| #20 V3.5.3 | V3 Web Frontend Security<br>V3.5 Browser Origin Separation | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | ⚠️ NEEDS_REVIEW | NEEDS_REVIEW - state-changing GET at `jip/src/Core/Browser/InterruptController.php:44` and `jip/src/Core/Browser/CallbackController.php:50` is required by the SBS and OIDC redirect protocols; no Sec-Fetch check; compensated by 256-bit state/ID and cookie binding; risk owner must accept |
| #21 V4.1.1 | V4 API and Web Service<br>V4.1 Generic Web Service Security | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | ✅ PASS | `[jip] jip/src/Core/Browser/BrowserPages.php:88` text/html; charset=UTF-8; JSON via JsonResponse application/json (`jip/src/Core/EngineBlock/AuthzController.php:85`) |
| #22 V4.4.1 | V4 API and Web Service<br>V4.4 WebSocket | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | ⚪ N/A | N/A - no WebSocket server or routes (searched: websocket, wss) |
| #23 V5.2.1 | V5 File Handling<br>V5.2 File Upload and Content | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | ⚪ N/A | N/A - no file upload endpoints (searched: UploadedFile, $_FILES, multipart) |
| #24 V5.2.2 | V5 File Handling<br>V5.2 File Upload and Content | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | ⚪ N/A | N/A - no file or archive acceptance |
| #25 V5.3.1 | V5 File Handling<br>V5.3 File Storage | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | ⚪ N/A | N/A - no files stored in jip/public (only index.php) |
| #26 V5.3.2 | V5 File Handling<br>V5.3 File Storage | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | ✅ PASS | `[jip] jip/src/Oidc/Cache/ProviderCache.php:38` sha256-hashed file names; `jip/src/Core/Storage/TransactionStoreFactory.php:26` path from operator config; outbound URLs https-only from config (`jip/src/Core/Configuration/Reader/ConfigNode.php:253`) |
| #27 V6.1.1 | V6 Authentication<br>V6.1 Authentication Documentation | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | ⚪ N/A | N/A - no credential entry; user authentication is delegated to DEZI (OIDC) |
| #28 V6.2.1 | V6 Authentication<br>V6.2 Password Security | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | ⚪ N/A | N/A - no local passwords |
| #29 V6.2.2 | V6 Authentication<br>V6.2 Password Security | Verify that users can change their password. | ⚪ N/A | N/A - no local passwords |
| #30 V6.2.3 | V6 Authentication<br>V6.2 Password Security | Verify that password change functionality requires the user's current and new password. | ⚪ N/A | N/A - no password change functionality |
| #31 V6.2.4 | V6 Authentication<br>V6.2 Password Security | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | ⚪ N/A | N/A - no registration or passwords |
| #32 V6.2.5 | V6 Authentication<br>V6.2 Password Security | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | ⚪ N/A | N/A - no password policy |
| #33 V6.2.6 | V6 Authentication<br>V6.2 Password Security | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | ⚪ N/A | N/A - no password input fields (pages contain no forms) |
| #34 V6.2.7 | V6 Authentication<br>V6.2 Password Security | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | ⚪ N/A | N/A - no password input fields |
| #35 V6.2.8 | V6 Authentication<br>V6.2 Password Security | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | ⚪ N/A | N/A - no password verification |
| #36 V6.3.1 | V6 Authentication<br>V6.3 General Authentication Security | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | ⚪ N/A | N/A - no credential authentication; DEZI owns it |
| #37 V6.3.2 | V6 Authentication<br>V6.3 General Authentication Security | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | ⚪ N/A | N/A - no user accounts |
| #38 V6.4.1 | V6 Authentication<br>V6.4 Authentication Factor Lifecycle and Recovery | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | ⚪ N/A | N/A - no initial passwords or activation codes |
| #39 V6.4.2 | V6 Authentication<br>V6.4 Authentication Factor Lifecycle and Recovery | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | ⚪ N/A | N/A - no password hints or secret questions |
| #40 V7.2.1 | V7 Session Management<br>V7.2 Fundamental Session Management Security | Verify that the application performs all session token verification using a trusted, backend service. | ✅ PASS | `[jip] jip/src/Core/Browser/CallbackController.php:89` transaction cookie verified server-side (hash_equals); `jip/config/packages/framework.yaml` session: false |
| #41 V7.2.2 | V7 Session Management<br>V7.2 Fundamental Session Management Security | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | ✅ PASS | `[jip] jip/src/Core/Browser/InterruptController.php:104` cookie value generated per attempt |
| #42 V7.2.3 | V7 Session Management<br>V7.2 Fundamental Session Management Security | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | ✅ PASS | `[jip] jip/src/Oidc/Jose/Base64Url.php:32` random_bytes(32); `jip/src/Core/Transaction/TransactionId.php:11` random_bytes(32) |
| #43 V7.2.4 | V7 Session Management<br>V7.2 Fundamental Session Management Security | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | ✅ PASS | `[jip] jip/src/Core/Browser/InterruptController.php:147` new cookie per provider attempt; `jip/src/Core/Browser/CallbackController.php:104` cleared after callback |
| #44 V7.4.1 | V7 Session Management<br>V7.4 Session Termination | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | ✅ PASS | `[jip] jip/src/Core/Result/ResultDelivery.php:58-62` consumed/expired transactions refused server-side; `jip/src/Core/Browser/CallbackController.php:71-75` |
| #45 V7.4.2 | V7 Session Management<br>V7.4 Session Termination | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | ⚪ N/A | N/A - no user accounts in JIP |
| #46 V8.1.1 | V8 Authorization<br>V8.1 Authorization Documentation | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | ✅ PASS | `[jip] jip/README.md:132` API token rule; `jip/README.md:141` organisation decision; `docs/2026-10-05-high-level-design-dezi-connector.md:1024` allowed_organisations |
| #47 V8.2.1 | V8 Authorization<br>V8.2 General Authorization Design | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | ✅ PASS | `[jip] jip/src/Core/EngineBlock/ApiTokenAuthenticator.php:20` constant-time API token check on /authz and /attributes |
| #48 V8.2.2 | V8 Authorization<br>V8.2 General Authorization Design | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | ✅ PASS | `[jip] jip/src/Core/Result/ResultDelivery.php:144` organisation allow-list per service; 256-bit transaction IDs |
| #49 V8.3.1 | V8 Authorization<br>V8.3 Operation Level Authorization | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | ✅ PASS | `[jip] jip/src/Core/EngineBlock/ApiTokenAuthenticator.php:20`; `jip/src/Core/Result/ResultAcceptance.php:44` server-side release filter |
| #50 V9.1.1 | V9 Self-contained Tokens<br>V9.1 Token source and integrity | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | ✅ PASS | `[jip] jip/src/Oidc/Jose/SignedMessageVerifier.php:79` JWSVerifier before claims are used |
| #51 V9.1.2 | V9 Self-contained Tokens<br>V9.1 Token source and integrity | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | ✅ PASS | `[jip] jip/src/Oidc/Jose/SignedMessageVerifier.php:54` alg must be RS256; AlgorithmManager([RS256]) at `:79` |
| #52 V9.1.3 | V9 Self-contained Tokens<br>V9.1 Token source and integrity | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | ✅ PASS | `[jip] jip/src/Oidc/Jose/SignedMessageVerifier.php:65-68` jku must equal approved address; `jip/src/Oidc/Keys/KeyResolver.php:36` keys only from configured address |
| #53 V9.2.1 | V9 Self-contained Tokens<br>V9.2 Token content | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | ✅ PASS | `[jip] jip/src/Oidc/IdToken/IdTokenValidator.php:74-81` exp, iat, nbf checked with skew |
| #54 V10.4.1 | V10 OAuth and OIDC<br>V10.4 OAuth Authorization Server | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | ⚪ N/A | N/A - JIP is an OIDC relying party, not an authorization server |
| #55 V10.4.2 | V10 OAuth and OIDC<br>V10.4 OAuth Authorization Server | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | ⚪ N/A | N/A - JIP does not issue authorization codes |
| #56 V10.4.3 | V10 OAuth and OIDC<br>V10.4 OAuth Authorization Server | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | ⚪ N/A | N/A - JIP does not issue authorization codes |
| #57 V10.4.4 | V10 OAuth and OIDC<br>V10.4 OAuth Authorization Server | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | ⚪ N/A | N/A - JIP does not grant tokens |
| #58 V10.4.5 | V10 OAuth and OIDC<br>V10.4 OAuth Authorization Server | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | ⚪ N/A | N/A - JIP issues no refresh tokens |
| #59 V11.3.1 | V11 Cryptography<br>V11.3 Encryption Algorithms | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | ✅ PASS | `[jip] jip/src/Profile/Dezi/UserInfoReader.php:87` JWE limited to RSA-OAEP + A256CBC-HS512 (no RSA1_5, no ECB) |
| #60 V11.3.2 | V11 Cryptography<br>V11.3 Encryption Algorithms | Verify that only approved ciphers and modes such as AES with GCM are used. | ✅ PASS | `[jip] jip/src/Profile/Dezi/UserInfoReader.php:87` AES-256 authenticated encryption (A256CBC-HS512, RFC 7518) |
| #61 V11.4.1 | V11 Cryptography<br>V11.4 Hashing and Hash-based Functions | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | ✅ PASS | `[jip] jip/src/Oidc/Token/ClientAssertionFactory.php:59` OPENSSL_ALGO_SHA256; `jip/src/Oidc/Pkce.php:23` SHA-256 |
| #62 V12.1.1 | V12 Secure Communication<br>V12.1 General TLS Security Guidance | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | ✅ PASS | `[jip] jip/src/Oidc/Http/ProviderHttpClient.php:61` outbound TLS 1.3 only; inbound TLS terminated at ingress (dev: `devenv/haproxy/generated/haproxy.cfg:49` no-tlsv10/no-tlsv11) |
| #63 V12.2.1 | V12 Secure Communication<br>V12.2 HTTPS Communication with External Facing Services | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | ✅ PASS | `[jip] jip/src/Core/Configuration/Reader/ConfigNode.php:253` https-only configured URLs; `jip/src/Oidc/Discovery/MetadataProvider.php:136` https-only discovered endpoints; `jip/src/Oidc/Http/ProviderHttpClient.php:58` no redirects |
| #64 V12.2.2 | V12 Secure Communication<br>V12.2 HTTPS Communication with External Facing Services | Verify that external facing services use publicly trusted TLS certificates. | ⚠️ NEEDS_REVIEW | NEEDS_REVIEW - certificate chain is a deployment property; verify the production ingress certificate for the JIP host |
| #65 V13.4.1 | V13 Configuration<br>V13.4 Unintended Information Leakage | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | ⚠️ NEEDS_REVIEW | NEEDS_REVIEW - no production build artifact in repo; verify the deployed image excludes .git (document root is jip/public) |
| #66 V14.2.1 | V14 Data Protection<br>V14.2 General Data Protection | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | ❌ FAIL | `[jip] jip/src/Core/Browser/CallbackController.php:54` code/state in query; `jip/src/Core/Browser/InterruptController.php:49` transaction ID in query |
| #67 V14.3.1 | V14 Data Protection<br>V14.3 Client-side Data Protection | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | ✅ PASS | `[jip] jip/src/Core/Browser/CallbackController.php:104` transaction cookie cleared; cookie expires at transaction deadline (`jip/src/Core/Browser/TransactionCookie.php:26`); no other client storage |
| #68 V15.1.1 | V15 Secure Coding and Architecture<br>V15.1 Secure Coding and Architecture Documentation | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | ❌ FAIL | `missing:dependency remediation time frames (searched jip/README.md, docs/*.md)` |
| #69 V15.2.1 | V15 Secure Coding and Architecture<br>V15.2 Security Architecture and Dependencies | Verify that the application only contains components which have not breached the documented update and remediation time frames. | ⚠️ NEEDS_REVIEW | NEEDS_REVIEW - no documented time frames (#68); `composer audit --locked` on 2026-10-23 found no advisories |
| #70 V15.3.1 | V15 Secure Coding and Architecture<br>V15.3 Defensive Coding | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | ✅ PASS | `[jip] jip/src/Core/Result/ResultAcceptance.php:44` only the service's `release` claims are returned |

---

## Conclusion

JIP's security posture is good for a POC that is heading towards acceptance. Its central trust decisions (API token, transaction state machine, OIDC/JOSE validation, organisation binding, attribute release) are enforced server-side, with strict allow-lists and constant-time comparisons. The four findings are hardening and governance gaps rather than exploitable flaws:

1. Add HSTS, in the application or at the production ingress (#16).
2. Rename the transaction cookie with the `__Secure-` prefix (#15).
3. Write down the dependency remediation and update policy and run `composer audit` in CI (#68), which also resolves #69.
4. Record the protocol-mandated URL parameters (#66) and the GET-based state transitions (#20) as accepted risks, and confirm that production logs exclude query strings.

Before go-live, also verify the deployment-dependent items #64 and #65 and the inbound TLS configuration of the production ingress.

Provenance note: the two evidence workers disagreed on items #14, #16, #20, #26, #40-#44, #66 and #69. The coordinator resolved each against the source code at commit f031f3c; it re-checked line references and ran `composer audit` itself.

**Signed:**  
Date: 2026-10-23  
Name: __________________
Signature:  
