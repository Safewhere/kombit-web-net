# Emergency access delivery record

Date: 2026-11-10. Scope: improved UI, automatic Passticket renewal after each accepted normal login, and existing emergency authentication compatibility.

## Build and automated evidence

- .NET Framework tests: 166 passed, zero failed or skipped. TRX: `TestResults/renewal-ui-final/ctt_CTTHANG-PC_2026-11-10_04_21_06.404.trx`.
- All five JavaScript test files passed with `node --test Kombit.Samples.CH.Emergency.Tests/*.test.cjs`.
- Website MSBuild passed; existing FxCop and IdentityModel dependency warnings remain. Log: `TestResults/ui-build-final.log`.
- ASP.NET compilation of the isolated package passed. Compiling the source directory directly is unsuitable because it contains a historical nested deployment configuration.
- A real local IIS Express request demonstrated the EndRequest completion redirect preserving the original path and query. This fixture was not deployed and was not a SAML integration test.
- Tests cover successive renewal before half-life, one request per accepted login under concurrency, account/browser isolation, skipped ineligible keys, deterministic selection, issuer failure, storage failure, retained counters, and emergency login with a renewed credential.
- Browser tests cover completion without WebAuthn, failure continuation, setup steps, duplicate submissions, minimisation, and active credentials remaining visible after an unsuccessful replacement.

## Deployment and live evidence

Deployed to `https://kombitspnew.safewhere.local/` at approximately 11:26 local time. IIS root: `C:\inetpub\wwwroot\kombitspnew`. Only the two application DLLs and nine changed/new presentation files were copied. Deployment verified file hashes and preserved Web.config and the encrypted registry. Existing external keys, settings, issuer trust and TLS binding were retained.

Backup: `C:\ProgramData\SafewhereSamples\DeployBackups\kombitspnew-ui-20261110-112556`. It contains the prior website and external emergency configuration/state with restricted directory access. Rollback should stop this site's pool and restore the changed application files from `website`; do not overwrite subsequently renewed state with the old backup during a routine code rollback.

Edge loaded the new HTTPS UI successfully. Normal login using the existing idpdemo federation session returned through the new completion page to My Page. At 04:27:01 UTC, the SP recorded `renew-after-login` HTTP 200 with Identify `POST emergency/renewals` HTTP 201. A second normal login at 04:27:49 UTC produced another independent 200/201 pair. Neither flow asked for a passkey. Management displayed the same registered binding as active, expiring December 10 at 11:27:49 local time.

A visible encoding defect on the completion page was corrected using HTML entities and redeployed. The next live completion page displayed the title and apostrophe correctly. No configuration change or CH2 deployment was required.

The emergency-login choice remained available. The user confirmed the existing passkey, and the deployed app reached EmergencyHome with an eight-hour session ending at 12:28:42 UTC. Local sign-out reached EmergencyEnded, and Sign in again returned to the chooser with Emergency login still available. No re-enrolment was needed.

## Manual acceptance checklist

| Scenario | Expected result | Evidence/status |
|---|---|---|
| Real normal login | Original destination reached, existing federation retained | Passed in Edge |
| Two successive normal logins | Two fresh issuer renewals; no additional passkey prompt | Passed, separate 200/201 log events |
| Existing registered key | Same binding remains active after deployment and renewals | Passed, management view |
| Completion text | Correctly encoded title and signed-in heading | Passed after correction |
| Setup dialog | Opening/minimising does not enrol; explicit confirmation starts setup | Automated plus local desktop/mobile UI check |
| Keyboard/mobile | Focus remains in modal, Escape minimises, narrow layout fits | Local Edge preview passed |
| Emergency login | User verifies existing passkey; saved claims and bounded session appear | Passed in Edge with existing passkey |
| Local emergency logout | Emergency session ends; registered key remains usable | Passed; chooser retained emergency option |
| Renewal failure | Normal login continues with clear warning; no blind retry | Automated |
| Issuer outage | Emergency login works using local credential validation | Automated; no live outage induced |
| Restart/storage compatibility | Existing registered key survives IIS deployment restart | Passed; no re-enrolment needed |

Normal SAML logout's existing idpdemo/CH2 signature error is excluded at the user's request. No live key removal or issuer outage was performed. Review was a source self-review, not an independent reviewer sign-off.

Screenshots retained locally in `TestResults/visual`: `deployed-login.jpg`, `deployed-keys.jpg`, `deployed-emergency.jpg`, and the synthetic desktop/mobile setup previews. They are not published externally.

See [technical setup](emergency-access-technical-setup.md) for configuration, contracts, deployment and recovery details.

## Visual refinement of the improved UI

Deployed November 10, 2026, at approximately 11:41 Asia/Saigon. This pass changes presentation and dialog navigation only; enrollment, removal, emergency authentication and automatic-renewal APIs remain unchanged.

- Setup now uses the reference's four-step progress rail, key-location explanation, browser confirmation, ready state and minimised reminder. The location step describes the configured authenticator; it does not offer unsupported options or change WebAuthn attachment policy. Only explicit confirmation at step three begins enrollment.
- Management opens in a native Settings dialog with a Login sidebar, login-method section, simpler passkey cards, and expandable technical identifiers. Removal retains its existing two-click confirmation and server operation. Session errors appear inside the dialog, and expired normal sessions no longer display a misleading full-access message.
- Sign-in is a compact single-column layout. The emergency session has a limited-access banner and card, with detailed restrictions under a disclosure.
- Edge verified the setup's first three steps with synthetic local status data, desktop/mobile sizing, and keyboard focus. No real key was registered or removed during this visual pass. Fresh-profile setup is still blocked by the separate idpdemo session-flush error observed in the comparison walkthrough.
- Edge verified the deployed management dialog with the existing real key, hidden technical details, mobile layout at 390px, Tab wrapping, Escape focus restoration, and reopening. Normal login refreshed the key to December 10, 11:41:48 local time without a passkey prompt.
- The five JavaScript test files passed after the changes. ASP.NET compilation passed. Existing .NET backend test evidence above remains applicable; backend code was not changed in this pass. Source self-review found and corrected stale-session wording and keyboard-focus handling.

Pre-refinement backup: `C:\ProgramData\SafewhereSamples\DeployBackups\kombitspnew-ui-20261110-114010`. Subsequent correction backup: `C:\ProgramData\SafewhereSamples\DeployBackups\kombitspnew-ui-20261110-114129`. Configuration and encrypted registry hashes were preserved during deployment. Icons use CSS, compatible with the existing CSP and IIS extension restrictions; no security configuration was relaxed.

Screenshots: `TestResults/visual/refined-setup-desktop.jpg`, `refined-setup-mobile.jpg` (local preview), `refined-settings-live.jpg` and `refined-settings-mobile.jpg` (deployed app).

## Portal home restructuring

The November 10 afternoon update replaces My Page's diagnostic-first layout with a compact portal header, navigation, access overview, and a small first-time setup reminder. Account claims, federation re-login buttons and service test controls remain under an expandable technical-tools section; no controls or backend handlers were removed. The account name is HTML encoded. The active stylesheet is now `EmergencyAssets/portal.css`; all master/page/project references use that name.

Validation: all five JavaScript test files passed; staged ASP.NET compilation passed with the existing duplicate-attribute warnings. Edge verified live normal sign-in, current-key readiness, opening and closing settings, account disclosure navigation, and a 390px mobile layout. Management showed renewed expiry at December 10, 14:32:49 Asia/Saigon. No key was registered or removed. Screenshots: `TestResults/visual/portal-home-live.jpg` and `portal-home-mobile.jpg`.

Deployment backup: `C:\ProgramData\SafewhereSamples\DeployBackups\kombitspnew-ui-20261110-143117`. Web.config and encrypted registry hashes were preserved. Historical backups retain their original filenames for rollback; the active application uses the neutral portal filename.

## Scenarios panel — November 11, 2026

The deployed panel provides forced/optional setup, a simulated normal-login outage, real emergency login, real renewal, a result log and reset. See the [presenter guide](emergency-access-scenarios.md).

- After the database server was started, Edge completed normal login through CH2 and idpdemo. My Page showed full access; the actual renewal result and key management both showed expiry December 11, 2026, 10:48:36 Asia/Saigon. No additional passkey prompt occurred.
- Reset removed the scenario banner and preserved both the normal session and the ready key.
- With the simulated-outage scenario selected, the user confirmed the existing passkey in Edge. Real emergency authentication succeeded at 10:49:58 Asia/Saigon; the session showed limited access with an eight-hour expiry. Behind the scenes recorded the successful server result. Screenshot: `TestResults/visual/scenarios-emergency-live.jpg`.
- Selecting renewal from the emergency session invoked local sign-out and reached EmergencyEnded. Its **Normal login** link reached `login.ashx?ReturnUrl=%2fMyPage.aspx`. Exiting the scenario cleared the banner, and the existing key remained available for emergency login.
- All six JavaScript test files passed, including scenario isolation, setup selection, outage auto-redirect suppression, reset and virtual-directory routing. `git diff --check` passed. Staged ASP.NET compilation passed before this walkthrough; the latest deployed correction changes JavaScript only.
- Initial deployment backup: `C:\ProgramData\SafewhereSamples\DeployBackups\kombitspnew-ui-20261111-104255`. The subsequent session-guidance JavaScript deployment was hash-verified without restarting the app pool.
- Renewal screenshot: `TestResults/visual/scenarios-renewal-live.jpg`. This pass does not claim live first-time enrollment or an actual CH2 outage.


## YubiKey walkthrough — November 11, 2026

The deployed authenticator preference was changed from `platform` to `any`, preserving the existing registry and key. Configuration backup: `C:\ProgramData\SafewhereSamples\DeployBackups\kombitspnew-yubikey-20261111-105532`.

The user completed security-key registration in Edge InPrivate. Management showed two active keys: the new key in this browser, initially expiring December 11 at 11:01:02 Asia/Saigon, and the existing key expiring at 10:56:15. The user confirmed successful YubiKey emergency authentication; the observed emergency page showed limited access and session expiry `2026-11-11 12:06:44Z`.

After the user signed out locally and completed normal login in the same InPrivate session, management showed the new key's expiry advanced to December 11 at 11:07:42. The existing key remained active with its prior expiry. This verifies renewal of the relevant browser key without replacing the existing key. The agent did not observe the intervening OS prompts; absence of a PIN/touch prompt on this particular normal login has not yet been explicitly confirmed by the user. Screenshot: `TestResults/visual/yubikey-renewal-live.jpg`.

Enrollment used InPrivate because renewal reserves the current normal-login reference, preventing another enrollment under that same reference. The additive setup button is available only when `can_prepare` is true; it does not override this restriction. All six JavaScript test files passed after that UI change.

## SQLite SP storage — November 11, 2026

The SP now persists encrypted records in `C:\ProgramData\SafewhereSamples\SamlEmergency\state\emergency.db`. Deployment resets SP state; there is no old-data migration. CH2 was not changed. The prior live YubiKey registration is deliberately absent from this fresh SP dataset; authenticator and issuer records were not deleted.

- All 168 .NET tests passed, including enrollment, renewal, emergency authentication, encrypted SQLite records, restart persistence, automatic creation, schema rejection, concurrent-writer rejection and failed-write recovery. All six JavaScript test files passed.
- Visual Studio web build passed. Existing IdentityModel NU1902 and legacy analysis warnings remain. SQLite native dependencies use bundle 2.1.12; the initial IIS assembly-binding issue was corrected with the explicit SQLitePCLRaw.core redirect in source and deployment.
- Ran the fresh-deployment script against the demo. HTTPS login returned 200. Edge normal CH2 login reached My Page and displayed fresh setup rather than stale-key readiness.
- Read-only inspection of the deployed database returned `integrity_check=ok`, schema version 1, a 12,288-byte database, and exactly one metadata record with no keys, credentials or sessions. Initialization required no manual SQL.
- Source review confirmed parameterized inserts, one transaction per bounded state update, protected record envelopes, no CH2 changes, and resets only in the deployment script. Review was a self-review.
- Read-only CH2 `SELECT DB_NAME()` probes during the preceding storage audit connected successfully to Identify, IdentifyAudit, IdentifyCache and IdentifySession. No application records or secrets were queried or modified.

Evidence: `TestResults/visual/sqlite-fresh-deployment.jpg`; test report `Kombit.Samples.CH.Emergency.Tests/bin/Debug/net48/TestResults/ctt_CTTHANG-PC_2026-11-11_04_33_34.492.trx`. The fresh SQLite deployment has not yet undergone another live physical-key enrollment/login/renewal walkthrough; those flows passed automated integration tests and the earlier live file-store walkthrough is historical evidence only.

### Fresh-enrollment blocker and scoped cleanup

The first fresh enrollment failed before the WebAuthn ceremony: SP reference `321f35c4c35444f886a9420a30c45716` recorded CH2 enrollment HTTP 409, surfaced as HTTP 502. Read-only issuer inspection subsequently confirmed two active bindings for the same demo subject and SP client; the reviewed issuer defaults to a two-registration limit. The SP reset had left these issuer bindings intact.

At the user's explicit request, both obsolete bindings were revoked using the authenticated, client-scoped CH2 `POST emergency/revocations` API. Each returned HTTP 204; a follow-up read confirmed both bindings had `Revoked=true`. The lookup matched both subject and client, and no other registrations were submitted for revocation. The issuer state file and its SQL protection-key repository were read only; no direct database/state-file edits or issuer configuration changes were made. Private authenticator credentials were not erased.

Edge was returned to the setup confirmation step for a new YubiKey registration. Live SQLite enrollment, emergency authentication and renewal results remain pending the physical-key confirmation and subsequent walkthrough.

The user subsequently completed fresh YubiKey setup. Edge displayed “Emergency access is ready”; key management showed one active key expiring December 11, 2026, 11:57:15 Asia/Saigon. Read-only SQLite inspection confirmed schema 1, integrity `ok`, a 20,480-byte file, and one row each in `keys`, `credentials` and `metadata`. The emergency-login scenario then reached the real passkey confirmation; authentication and subsequent renewal are still pending.

### Completed live SQLite walkthrough

On November 11, 2026, the user confirmed the newly registered YubiKey for emergency login. Edge reached `EmergencyHome.aspx`, displayed limited access and session end `2026-11-11 12:58:59Z`. Local sign-out reached `EmergencyEnded.aspx`; its Normal login link reached `login.ashx?ReturnUrl=%2fMyPage.aspx`. Selecting CH2 completed normal SAML login using the existing SSO session.

The completion page automatically refreshed emergency access and returned to My Page. No additional passkey interaction was needed during this observed normal-login flow. Key management showed the same single browser key, with expiry advancing from December 11 at 11:57:15 to 11:59:47 Asia/Saigon. SP diagnostics recorded `renew-after-login` HTTP 200 at 11:59:48 and CH2 `POST emergency/renewals` HTTP 201 (reference `ff2e3b9426d04dfd8be3699edf140048`).

Post-flow read-only SQLite inspection returned integrity `ok`, schema 1, 36,864 bytes, one key, two credential records and one metadata record. Credential row count includes stored issuance history; it is not a count of active keys. No emergency session row remained after local sign-out. These results complete the previously pending live enrollment, emergency-login and automatic-renewal walkthrough with SQLite.

Screenshots: `TestResults/visual/sqlite-emergency-success.jpg` and `TestResults/visual/sqlite-renewal-success.jpg`.
