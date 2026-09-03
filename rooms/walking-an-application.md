# Walking An Application

**Category:** Web Application Security — Manual Recon
**Tools used:** Firefox DevTools only (no automated scanners)
**Link:** [TryHackMe Room](https://tryhackme.com/room/walkinganapplication)

---

## Objective

Manually assess a web application (Acme IT Support) for information disclosure and misconfiguration issues using only browser-native tools: View Source, Inspector, Debugger, Network, and Storage — no automated scanners.

---

## Methodology

### 1. Site Mapping
Walked the application and catalogued all discoverable pages/endpoints and their functionality before touching DevTools:

| Feature | Endpoint | Summary |
|---|---|---|
| Home Page | `/` | Company summary + staff photo |
| Latest News | `/news` | List of articles, each with `?id=` parameter |
| News Article | `/news/article?id=1` | Individual article; some gated as "premium" |
| Contact Page | `/contact` | Contact form (name, email, message) submitted via AJAX |
| Customers | `/customers` | Redirects to login |
| Customer Login | `/customers/login` | Username/password form |
| Customer Signup | `/customers/signup` | Registration form |
| Password Reset | `/customers/reset` | Email-based reset |
| Customer Dashboard | `/customers` | Ticket list + "Create Ticket" |
| Create Ticket | `/customers/ticket/new` | Issue form + file upload |
| Account | `/customers/account` | Edit username/email/password |
| Logout | `/customers/logout` | Ends session |

**Takeaway:** parameterized URLs (`?id=`) and file upload functionality are immediate candidates for deeper testing (IDOR, file upload validation) in a full assessment.

### 2. Page Source Review
Viewed raw HTML source (`view-source:`) on the homepage:
- Found an **HTML comment** disclosing a temporary/beta homepage path not linked anywhere in the nav.
- Found a **hidden `<a>` link** to a `secret-page`-style path, not present in the visible navigation — a private/undocumented area.
- Reviewed `<script src>` / `<link>` tags referencing a shared `/assets/` directory.

### 3. Directory Enumeration
Browsed directly to the `/assets/` directory referenced by the static includes:
- Directory listing was enabled (misconfigured web server — `Options -Indexes` / `autoindex` not disabled).
- A `flag.txt` file was present and readable — demonstrates how directory listing can expose backups, leftover files, or source code in real environments.

### 4. Framework Fingerprinting
Found a footer comment naming the framework and version in use. Cross-referenced the vendor's site and confirmed the deployed version was outdated relative to the latest release notice — a real finding, since outdated frameworks often carry known CVEs.

### 5. DOM Manipulation (Inspector)
On the News page, a "premium" article was blocked by a floating paywall `<div class="premium-customer-blocker">`.
- Inspected the element, located the CSS `display: block` rule controlling it.
- Changed it to `display: none` directly in the Styles panel — this revealed the "premium" content underneath.
- **Real-world significance:** the content was already delivered to the client and only hidden by CSS — i.e., access control was enforced in the presentation layer, not the backend. That's a legitimate finding class (client-side-only authorization).

### 6. JavaScript Analysis (Debugger/Sources)
On the Contact page, a red UI element flashed briefly on load.
- Opened the Debugger tab, located `flash.min.js` under `/assets/`.
- Used **Pretty Print** to reformat the minified/obfuscated script.
- Found the line `flash['remove']();` responsible for removing the element.
- Set a **breakpoint** on that line, refreshed the page — execution paused before removal, letting the element (and the flag it contained) persist on screen.
- **Real-world significance:** demonstrates how breakpoints let a tester intercept and inspect client-side logic before it executes/hides something, which is directly applicable to bypassing or understanding client-side validation.

### 7. Network Traffic Analysis
With the Network tab open, submitted the Contact form:
- Captured the resulting AJAX `POST` request to a `contact-msg`-style endpoint.
- Reviewed the **Response** tab — the raw JSON/HTML response contained data not otherwise rendered in the UI.
- **Real-world significance:** background API calls often receive less scrutiny than the main site and are worth testing independently (e.g., in Burp/Postman) for auth bypass, injection, or excessive data exposure.

### 8. Client-Side Storage Review
Registered a test account at `/customers/signup`, logged in, then opened the Storage tab:
- Inspected the session cookie under **Cookies**.
- Found `HttpOnly` was **not set** (`false`) on the session cookie.
- **Real-world significance:** without `HttpOnly`, JavaScript can read the session cookie via `document.cookie`. Combined with any XSS elsewhere in the app, this directly enables session theft. `Secure` and `SameSite` should also be checked on any session/auth cookie.

---

## Findings Summary

| # | Finding | Typical Severity | Recommendation |
|---|---|---|---|
| 1 | Sensitive info in HTML comments | Low–Medium | Strip developer comments from production builds |
| 2 | Unlinked/hidden page discoverable via source | Low–Medium | Enforce real access control rather than relying on obscurity |
| 3 | Directory listing enabled, file disclosure | Medium–High | Disable directory indexing; remove stray files from web root |
| 4 | Outdated framework version | Medium–High (CVE-dependent) | Patch/upgrade to latest stable release |
| 5 | Client-side-only content restriction (CSS paywall) | Medium–High | Enforce entitlement checks server-side before sending data |
| 6 | Client-side JS controls security-relevant UI behavior | Low–Informational | Don't rely on obfuscated JS as a security control |
| 7 | Verbose AJAX response data | Low–Medium (context-dependent) | Return only the data the UI actually needs |
| 8 | Session cookie missing `HttpOnly` | Medium–High | Set `HttpOnly`, `Secure`, and `SameSite` on all session/auth cookies |

---

## Key Techniques — Reusable Cheat Sheet

| Tool/Action | What you're hunting for |
|---|---|
| View Page Source | Comments, hidden links, asset paths, framework/version fingerprint |
| Directory browsing on asset paths | Directory listing misconfig → backups, source, config exposure |
| Inspector — edit CSS live | Client-side-only access control / hidden content |
| Debugger/Sources — Pretty Print + breakpoints | Client-side validation logic, hardcoded secrets, obfuscated logic |
| Network tab | Hidden AJAX/API endpoints, verbose responses, parameter tampering surface |
| Storage tab — Cookies | Missing `HttpOnly` / `Secure` / `SameSite` flags |
| Storage tab — Local/Session Storage | Tokens/secrets stored insecurely (always JS-readable, no HttpOnly equivalent) |

---

## Interview Talking Points

**Q: Walk me through your process when you first land on a web application during an assessment.**
> I start with manual reconnaissance using only the browser — no scanners yet. I map the site by walking through every page and feature, noting endpoints and functionality. Then I view page source for comments and hidden links, check for directory listing on static asset paths, and use DevTools to review the DOM, JavaScript, network traffic, and client-side storage. This builds context before I bring in tools like Burp Suite for active testing.

**Q: Give an example of a real vulnerability class you can identify using just browser DevTools.**
> Missing `HttpOnly` on a session cookie, checked in the Storage tab — without it, any XSS elsewhere in the app becomes far more severe since JavaScript can read and exfiltrate the session cookie directly. Another example is content restricted only via CSS rather than server-side authorization: the "protected" data is actually delivered to every client, just visually hidden.

**Q: Why bother with manual testing when scanners exist?**
> Scanners pattern-match known signatures but miss business logic flaws and anything requiring understanding of what the app is trying to do — like a paywall that's only enforced in CSS, not the backend. A trained eye reading comments, JS logic, and API responses catches things a scanner has no way to flag.

---

## Conclusion

This room demonstrates that a meaningful amount of an application's attack surface and misconfiguration can be identified with zero automated tooling — just a browser and a methodical process across View Source, Inspector, Debugger, Network, and Storage. This recon phase should precede active/automated testing, since it builds context (endpoints, logic, framework version, cookie posture) that shapes and prioritizes later exploitation work.
