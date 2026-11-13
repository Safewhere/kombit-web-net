# Emergency access technical PoC completion plan

Status: implemented and deployed to kombitspnew.safewhere.local; verification and deployment evidence is tracked in [the delivery record](docs/emergency-access-verification.md). Date: 2026-11-10.

The user accepted current-browser renewal on 2026-11-10; its selection rules are specified in work package 7. Identify PR 11976 at `3551374428` supports prompt-free renewal with a newer normal-login reference, and the owner confirmed dev520 runs that implementation. No CH2 changes are required. The normal SAML logout exclusion below is not a delivery blocker.

Implementation uses a completion redirect after OIOSAML selects the original return URL; the completion page submits browser marker IDs through the existing CSRF/origin-protected API. No renewal occurs on widget load. Storage failures preserve prior durable credentials but retain the existing fail-closed registry policy until recovery. Live deployment and successive normal-login renewals passed on November 10; post-deployment emergency login with the existing passkey and local logout also passed.

## Objective

Complete the owner's three deliverables:

1. Apply the improved UI from `E:/Github/kombit-emergency-access-main` into the actual Web Forms application connected to the existing CH2 development tenant (Identify), demonstrating real authentication and persisted records.
2. Automatically renew existing Passtickets on every successful normal login without another YubiKey/WebAuthn confirmation.
3. Deliver approximately 3–4 pages of Markdown technical setup documentation for the final demo.

Retain the existing emergency backend, API contracts, storage, and authentication boundaries. Renewal frequency is the explicit exception to the previous behavior-preservation scope. This is no longer a presentation-only implementation.

Working terminology: “Passticket” means the Identify-issued emergency credential bound to an existing passkey. Renewal issues a replacement credential and refreshes its claims snapshot; it does not register or replace the passkey. Verify this terminology against the deployed issuer before implementation.

Implement with ASPX/master-page markup, scoped CSS, and the existing vanilla JavaScript. No Vue, Tailwind build pipeline, simulated authentication, or replacement backend is needed.

## Scope and behavior boundaries

- Preserve all `EmergencyApi.ashx` operations, request/response fields, CSRF handling, cookies, authorization checks, reference IDs, and issuer-call diagnostics.
- Preserve the existing passkey options and `EmergencyCredential.Authenticator` preference. The prototype's device-choice step must not override deployment configuration or add transport restrictions.
- Preserve single-step server activation and one-use normal-login preparation. Replace the half-lifetime renewal trigger with renewal on each newly accepted normal CH2 login, subject to the renewal contract below. Keep normal login usable if renewal fails; never silently claim a failed renewal succeeded.
- Preserve browser marker format, migration from old IndexedDB copies, multiple keys/accounts, marker cleanup, and server-only credential storage.
- Preserve current login visibility and automatic normal-IdP continuation. A locally active marked key remains available under the current rules, even when Identify is online. Do not introduce health probes, outage-only gating, automatic emergency fallback, new delays, or status polling.
- Preserve removal confirmation and local logout. No new annual rotation, manual renewal workflow, global key, device restriction, or administrative blocking workflow.
- Preserve actual session expiry and claims, including historical claims and local session controls. No new permission model or generic promise of “limited access”; explain the sample's existing SAML/STS restrictions accurately.
- Keep setup user-initiated. Adopt the guided dialog and optional minimised reminder without automatically opening setup on first login or forcing completion.
- Keep all existing routes and return URLs. Existing normal-login, SAML, STS, and service-call UI remains functional.
- Normal SAML logout's existing idpdemo signature-verification failure is explicitly out of scope at the user's direction. Do not investigate or fix it as part of this work, and do not block UI/renewal delivery on it. This overrides the baseline note suggesting separate tracking. Emergency local logout remains in scope and has passed the baseline walkthrough.

## Proposed screen mapping

### Live prototype walkthrough evidence (2026-11-10)

Walked through `https://kombit-emergency-access.vercel.app/` in the browser: KOMBIT normal-login transition, setup introduction and authenticator choice, waiting state, minimisation/reopening, preset emergency login, emergency-session banner, Settings/Login claims and credential disclosure, and the outage-without-key screen.

The deployed default is **Simple + Universal**: a compact three-step setup dialog with neutral dark buttons and a bottom-right reminder, inside the red/beige KOMBIT shell. Use this observed default as the visual reference for setup; the main sign-in action remains KOMBIT red. A universal setup appearance here is a fixed visual treatment, not a user-selectable theme feature.

Settings is a large dialog with a quiet left navigation area and an independently scrolling content area. Readable claims precede expandable credential JSON. The emergency session uses a slim tinted banner below navigation with expiry aligned at the right. The no-key screen offers clear next steps instead of a generic error; adapt that writing style only to states the actual app can establish.

Setup did not complete: it remained at “Waiting for Windows Hello” in the embedded browser, so success-state details remain source-derived. Preset simulated emergency login did complete. This walkthrough did not verify real WebAuthn, responsive breakpoints, key removal, or all renewal/error variants; those remain implementation-validation tasks. No live CH2 behavior was exercised.

| Existing surface | Proposed presentation | Behavior/data source |
|---|---|---|
| `LoginOptions.aspx` | Branded sign-in layout; normal IdP choices plus a clear emergency card, one primary passkey button, busy/error states | Existing `login-status`, `login-options`, `login-complete`, and auto-continue logic |
| Setup widgets on `Default.aspx` and `MyPage.aspx` | Compact readiness card and an explicit “Set up emergency access” entry; guided explanation → confirmation → success dialog | Existing `status`, `can_prepare`, enrollment and activation flow |
| `Emergency.aspx` via `Emergency.Master` | Focused “Login / Emergency access” management view inspired by Settings; account keys grouped by marker association | Existing account credentials; removal remains two-click |
| `EmergencyHome.aspx` via `Emergency.Master` | Persistent emergency-session banner, real expiry, local sign-out, readable claims and expandable technical details | Existing principal and `SessionCredential`; no new requests |
| `EmergencyEnded.aspx` | Clear signed-out/session-ended presentation with existing navigation | Existing ended route and logout behavior |

The Settings treatment will cover emergency access only. Do not introduce empty General/Profile sections, a dummy user menu, or an Aula application shell.

## Ordered work packages

### 1. Capture baseline and interaction contracts

Record screenshots and request sequences for normal login, setup, ready state, used/lost preparation record, emergency login, key removal, and local logout. Record disabled-feature and unsupported-browser states. Use isolated test data for enrollment/removal checks.

Inspect existing browser tests and their DOM assumptions before changing markup. Document which selectors are public hooks for the scripts and which can be updated together. Treat the current source as authoritative where prototype behavior differs.

Confirm the current deployment from `README-emergency-setup-dev520.md` against actual IIS and Identify configuration; historical setup records alone are not current evidence. Record the SP URL, tenant/SAML entity ID, connection, issuer audience, runtime URL, public trust identifiers, deployment paths, and persistence locations without recording secrets. Verify the real normal SAML callback and issuer capture before changing renewal.

Completion: a screen/state checklist, baseline checks, and verified environment map are available. Identify the precise client changes and any issuer dependency needed for the revised renewal rule.

### 2. Introduce a shared visual foundation

Adapt the reference's KOMBIT red, warm neutral surfaces, card treatment, typography hierarchy, buttons, badges, spacing, and focus styles. Use scoped emergency classes/tokens in `EmergencyAssets/emergency.css` and carefully bounded integration in `css/Style.css` and `sp.Master`. Align `Emergency.Master` with the same appearance.

Use existing local brand assets. Any added font/icon asset must be locally packaged and compatible with current response headers. Avoid global Bootstrap overrides. Keep the normal application usable at narrow viewport widths; add viewport metadata where needed.

Completion: sign-in and emergency pages share a coherent visual language without styling regressions on normal sample controls.

### 3. Redesign sign-in presentation

Update `LoginOptions.aspx` and the presentation portions of `EmergencyAssets/login-options.js`. Preserve configured IdP choices, unavailable-metadata state, all links, marker checks, and continuation decisions.

Add a clear emergency card, neutral passkey wording, progress feedback, retryable errors, and support references. Do not name the prepared user before authentication. Do not assert that Identify is down: the backend does not supply that fact. A missing active marker retains today's normal-login path rather than displaying the prototype's simulated outage screen.

Completion: every existing login outcome and redirect is unchanged; emergency login still makes no Identify call.

### 4. Add guided setup presentation

Update the two setup widgets and `EmergencyAssets/setup.js`. Default to the reference's simple dialog, with an explanation, one explicit confirmation action, and success details based on the returned expiry. Keep a stepper as a future visual option rather than shipping two layouts initially.

Opening or minimising the dialog must not start enrollment, consume a login record, or trigger another status/renewal cycle. The existing setup action owns enrollment and the WebAuthn prompt. Disable duplicate submissions and preserve cancellation/error handling. An optional dock restores an already-opened dialog; it is presentation state only.

Show ready, setup available, sign-in-again required, unsupported browser, loading, and unavailable states. Consume the renewal outcome from work package 7 rather than starting a second renewal. The dialog must not compete with renewal for the preparation record. Explain when a fresh login is needed to add a key after the login record has been used for renewal.

Completion: one user confirmation triggers the existing registration flow, no extra WebAuthn prompt is added, and successful setup immediately becomes ready.

### 5. Redesign management and session views

Update `Emergency.Master` and rendering in `EmergencyAssets/emergency.js`; keep `EmergencyFeature/EmergencyPage.cs` unchanged unless presentation-only data formatting is necessary.

Group keys as “Set up in this browser” and “Other registered keys.” The API exposes binding IDs, status and expiry, not trustworthy device names, operating systems, or authenticator labels. Do not invent phone/tablet entries or imply that synced passkeys are confined to a device. Retain multiple registrations and existing status handling.

Present removal consequences inline and keep the existing two-click confirmation behavior. Do not adopt the prototype's eight-second timer without a separate behavioral decision.

On the emergency home page, place the session banner and actual end time first. Put claims, decrypted credential details, and explanation behind accessible disclosures. Retain all existing diagnostic information, escaping, and exclusion of the session secret. Keep the issuer-results panel available but visually secondary.

Completion: management uses real records, removal still ends associated sessions, and the emergency home page preserves all available information with clearer hierarchy.

### 6. Verify and package

- Run the existing browser checks: `SetupFlow.test.cjs`, `LoginOptionsAutoContinue.test.cjs`, `BrowserLifecycle.test.cjs`, and `AuthenticatorHints.test.cjs`. Update DOM-dependent assertions without weakening their behavioral intent.
- Add focused interaction coverage for dialog focus/restore, duplicate submission prevention, dismiss/reopen without enrollment, and the required login/renewal request sequences from work package 7.
- Build with Visual Studio MSBuild and the deployment-copy event disabled, following `README-emergency.md`; compile/render ASPX pages and run the existing emergency .NET tests.
- Verify in a browser: keyboard-only operation, focus trapping/restoration, Escape/minimise rules, live announcements, visible focus, contrast, zoom, long claims/errors, and mobile widths. Buttons inside the Web Forms form must not accidentally submit it.
- Verify feature disabled, no key, multiple keys, used login record, cancellation, renewal failure, removed/expired key, missing marker, session expiry, local logout, and normal SAML/STS controls.
- Verify with an unavailable issuer that emergency login, home, and logout remain local. Use request traces rather than the UI wording as evidence. Exercise virtual-directory paths and configured authenticator preferences.
- Register new local assets in `Kombit.Samples.CH.WebsiteDemo.csproj`; verify package contents and cache-busted asset URLs. Do not hand-edit generated Deployment copies. Live deployment is a separate delivery step in work package 8.

Completion: applicable tests/build and visual checks pass, any environment-dependent checks are explicitly recorded, and the diff is limited to the UI, required renewal changes, packaging, tests, and documentation.

### 7. Renew Passtickets on every normal login

Schedule this after baseline discovery and before completing setup integration and final verification (packages 4 and 6). Existing package numbers are retained for traceability.

**Required contract**

- A newly accepted normal SAML login triggers one coordinated renewal attempt for the selected active registration associated with the current browser and authenticated account, even if the current credential was issued moments ago. Reloading a page or visiting another page in the same session is not a new normal login.
- Use the fresh accepted assertion reference and existing issuer renewal flow; retain the same binding and passkey. Do not call `navigator.credentials.create()` or `navigator.credentials.get()` for renewal, request ForceAuthn, or force another CH2 login just to renew.
- Validate and activate the replacement through the existing server checks. Display the actual returned validity and fresh claims; do not merely advance a browser expiry or impose the prototype's annual rotation date.
- With no matching active registration (including a missing browser marker), skip renewal without consuming the record so setup can proceed. Never fall back to an unrelated account registration. Expired, blocked, revoked, removed, and pending registrations are ineligible for this automatic renewal policy.
- Deduplicate concurrent tabs, refreshes, and repeated UI initialization on the server against the accepted login record. No repeat issuance from the same record and no blind retry after an ambiguous issuer timeout.
- A failed renewal must leave the prior usable credential and normal session intact. Record a sanitized failure/reference, communicate that validity was not extended, and retry on the next new normal login under the existing single-use constraints. Test persistence and activation failures as well as issuer failures.

**Implementation investigation and affected components**

Trace `EmergencyNormalLoginAction.LoginAction`, `EmergencyWeb.NormalHandle`, `EmergencyAccess.RecordLogin`/`Renew`, and the API's activation helper. The current widget uses `renew_due`, chooses one account binding, and executes only on the home/My Page widgets. Simply deleting the half-lifetime condition does not prove renewal for every normal-login return path.

Use a coordinated post-login integration independent of whether the final return page contains a setup widget. The current browser association lives in localStorage, so the SAML callback cannot determine it by itself. Inspect OIOSAML's callback/redirect lifecycle and use a protected post-login completion step to read and submit marker binding IDs, unless an existing verified server-side association can supply equivalent context. Treat IDs as hints, authorize ownership and eligibility on the server, and retain CSRF/origin checks and server-side deduplication. Await and record the outcome before continuing to the validated original return URL. Do not introduce untracked background work or sync-over-async in the callback. Keep endpoint contracts where possible and record any necessary integration changes. If JavaScript/storage is unavailable, normal login remains usable but renewal cannot be claimed successful; include this limitation in the guide.

Remove the widget's half-life scheduling responsibility once the login integration owns renewal. Keep `renew_due` backward-compatible if other callers need it. Synchronize browser markers from the real status result on rendered pages, and verify that another browser's stale expiry marker does not hide a successfully renewed registration. Any required change to marker reconciliation must be explicit and tested; it must not store credentials in the browser.

**Accepted product decision: one relevant current-browser registration**

Renew one Passticket per fresh normal login, reusing its passkey. Intersect marker binding IDs with the authenticated account's active, unexpired server registrations. If multiple bindings qualify, select the binding whose active credential has the latest issuance time; use ordinal binding ID order as a deterministic tie-breaker. This selection detail avoids another user prompt and fits the existing one-use login record. Leave every other binding unchanged; do not loop over account keys or weaken replay protection.

Browser markers are association hints, not authentication or proof of physical-device confinement. A synced passkey remains subject to existing login behavior. Never infer a specific authenticator/device from the marker. Validate the selected binding again when reserving the record and activating the replacement.

Add multi-key/multi-account cases: two marked keys select exactly one deterministically; a newer unmarked account key is not selected; foreign-account, expired, blocked, removed and unknown IDs are ignored; no eligible match preserves setup eligibility. Verify untouched bindings retain their previous credential and expiry.

**Acceptance evidence**

Perform two successive real CH2 normal logins less than half a credential lifetime apart. Each must issue and activate a new credential for the agreed binding scope, with the same passkey/binding, fresh issuance/expiry, and the new login's claims snapshot. Neither login may show an extra passkey prompt for renewal. Verify refresh/concurrent-tab deduplication, arbitrary supported return paths, absent marker, no key, expired/blocked key, and failure preservation. Emergency login must still request passkey verification and work without Identify after renewal.

### 8. Deliver and verify the real CH2 development demo

Depends on packages 1–7 passing applicable local checks. Prepare a concrete deployment package and rollback procedure, then deploy to the agreed existing development site as a separately authorized execution step; this plan update itself makes no live changes.

- Use the current Identify tenant and real SAML/issuer endpoints. Exclude the reference prototype's scenario switch, simulated keys/users, local fake registry, and fake backend-call history from the final demo.
- Preserve existing encryption keys, ASP.NET machine key, trust, external settings, and protected state. Back up the application/configuration/state consistently before deployment, and account for any required issuer update. Never copy secrets into source or documentation.
- Record the persistence actually used: the sample uses a protected file registry, not a new SQL database. Document Identify's actual issuer persistence and normal user storage after verifying them. “Real databases” means actual backend records, not a requirement to replace working storage without further scope.
- Verify real normal login, real passkey enrollment, automatic renewal on subsequent normal logins, key management, emergency sign-in, claims display, and logout. Retain evidence that records survive an application-pool restart and that fresh normal login is required when transient preparation evidence is lost.
- Demonstrate issuer unavailability using an isolated test arrangement that does not interrupt other users of the shared tenant. Emergency sign-in/home/logout must make no issuer request. Restore the test environment afterwards.
- Test with a physical YubiKey or a real supported platform passkey in an external browser. A virtual authenticator alone does not satisfy the final real-flow demonstration. Record human-operated prompts where needed.

Completion: final demo URL, deployed versions, environment map, concise walkthrough, renewal evidence, persistence evidence, and known limitations are recorded. Mark missing live checks as pending, not passed.

### 9. Write the technical setup guide (approximately 3–4 Markdown pages)

Create `docs/emergency-access-technical-setup.md` and link it from `README-emergency.md`. Draft alongside implementation and reconcile it with the verified deployment in package 8. Markdown has no fixed pagination; target four compact sections, roughly 1,200–1,800 words plus a small diagram/configuration examples.

1. **Architecture and flows:** browser, Web Forms SP, CH2/Identify, issuer, real persistence; normal login, initial setup, every-login renewal, and offline emergency login. Clearly distinguish a passkey, Passticket, and emergency session.
2. **Prerequisites and configuration:** build/runtime, IIS/HTTPS, trusted certificate, SAML metadata/entity IDs/connection, issuer client/audience/origin/RP ID, API-key provisioning, signing trust, encryption key, stable machine key, file paths/ACLs and single-worker constraint. Use placeholders for secrets.
3. **Build, deployment and operation:** reproducible commands, configuration locations, package contents, restart sequence, preserving state/keys, safe backup/rollback, and exact renewal trigger/failure behavior including the resolved multi-key scope.
4. **Verification and troubleshooting:** short real demo script, expected calls and prompts, persisted-record evidence, reference-ID/log lookup, typical configuration failures, outage demonstration, and known PoC limits.

Use small Mermaid sequence/architecture diagrams where helpful. Include verified environment identifiers as appropriate, never API keys, private keys, cookies, raw credentials, or personal claims. Replace contradictory half-lifetime renewal guidance in the existing README; preserve historical setup records as explicitly historical.

Completion: someone with the stated prerequisites can follow the guide to configure and demonstrate the solution; commands, paths, behavior, and links match the final tested deployment.

## Owner requirement traceability

### Deployed baseline evidence (2026-11-10)

- Normal SAML login through idpdemo and CH2 dev succeeded. Signing-key and revocation synchronization displayed HTTP 200.
- Corrected only the SP's IIS HTTPS binding to the existing trusted certificate with a `*.safewhere.local` SAN. Normal HTTPS validation returned 200. The embedded browser continued rejecting WebAuthn on TLS grounds; testing continued in Edge.
- The user completed real passkey registration in Edge. The management page showed one active key associated with this browser, with a credential expiring December 10, 2026.
- Emergency login with user passkey confirmation succeeded and displayed the saved claims and an eight-hour emergency session. Visiting `MyPage.aspx` redirected to `EmergencyHome.aspx` while that session was active.
- Local emergency logout succeeded and returned to `EmergencyEnded.aspx`. Its sign-in link opened the normal `login.ashx` chooser with Emergency login still available; the key was retained.
- Separate baseline defect: normal SAML Logoff reached idpdemo's logout endpoint, which reported inability to verify the CH2 request signature. The normal app session remained active. The first emergency-login test therefore used `LoginOptions.aspx` directly to switch sessions. Track the federation logout issue separately from the UI migration; do not claim normal SLO passed.
- No issuer outage was induced, no key was removed, and automatic renewal/restart persistence were not tested in this walkthrough. The existing deployed explanation still describes half-lifetime renewal. The owner's every-login requirement remains implementation work.

| Requirement | Work packages | Completion evidence |
|---|---|---|
| Improved UI in the real CH2-connected app | 1–6, 8 | Real tenant login, real enrollment/persistence, working styled screens, final demo URL |
| Renew on every normal login without WebAuthn reauthentication | 7, 4, 6, 8 | Successive fresh logins renew before half-life, unchanged passkey, no renewal prompt, deduplication/failure tests |
| Technical setup documentation | 9 | Reviewed 3–4-page-equivalent Markdown guide matching the deployed setup |

## Assumptions and delivery

Use English initially, matching the current app. Danish localisation, a universal alternative theme, notification-bell infrastructure, and the prototype's experimental flows are outside this change. Current-browser renewal is accepted; issuer compatibility and post-login integration are implementation checks in packages 1/7, not open product-scope decisions.

Execution order: baseline (1), renewal contract/integration (7) and visual foundation/sign-in (2–3), setup/management (4–5), verification/package (6), real deployment/demo (8), final documentation (9). Draft documentation throughout. Review the UI and renewal changes separately. No state migration or re-enrollment is intended; verify credential/state compatibility before rolling back application or issuer versions. Reverting the UI alone does not revert renewal behavior.

Primary reference: `E:/Github/kombit-emergency-access-main/src/components/emergency/`, `src/composables/useSignIn.ts`, `src/components/SettingsDialog.vue`, and `src/style.css`. Current contracts live in `Kombit.Samples.CH.WebsiteDemo/EmergencyFeature/EmergencyApi.cs` and `Kombit.Samples.CH.Emergency/EmergencyAccess.cs`.
