# Presenting emergency-access scenarios

Open the deployed app in Edge and expand **Scenarios** at the bottom left. The panel controls this tab's demo journey. Authentication, key registration, ticket renewal and key validation use the existing backend.

| Scenario | Presenter steps | Expected result |
| --- | --- | --- |
| Forced setup | Choose **Set up emergency access → Forced**, then complete normal login. Use a browser/account without an eligible key. | Setup opens automatically. Registering a key still requires explicit confirmation and WebAuthn. |
| Optional setup | Choose **Not forced**, then complete normal login. | A browser without a key shows the setup reminder; the presenter chooses when to open it. |
| Normal login unavailable | Choose **Emergency login → Normal login unavailable**. | A DEMO banner identifies the simulated outage. Normal-login links on this chooser are withheld; CH2 remains running. Use **Emergency login** and confirm the existing passkey. |
| Emergency with a key | Choose **Emergency with a key**, then **Emergency login**. | The server verifies the real passkey and creates the existing bounded emergency session. A usable registered key is required. |
| Renewal | Choose **Renew emergency access → Renew after normal login**, select CH2, then idpdemo and **Log in**. | One eligible key for this browser is renewed without another passkey prompt. **Behind the scenes** records the actual renewal result and expiry. |

An existing ready key is never removed to demonstrate first-time setup. Forced and optional setup record that enrollment was skipped when this browser already has a ready key. Use a separate browser/account to demonstrate enrollment from scratch.

Selecting a new scenario from an active emergency-session page uses its existing local sign-out action. Continue with **Sign in again** on the session-ended page. If the login chooser cannot offer emergency login, the guidance links to the emergency-session page to check for an existing session.

**Reset scenario** and **Exit scenario** clear only the panel's session-storage entry and return to My Page. They do not delete registered keys, clear the browser key marker, or sign out the normal session. Other tabs are not configured by this panel.

**Behind the scenes** keeps up to twelve messages in this tab. Success messages come from completed server responses; selecting a scenario alone is not evidence of successful authentication. The outage is a presentation simulation, not a test of an actual CH2 outage. Expired-key, blocked-key and global-key previews are outside this initial panel.

Implementation: [scenario controller](../Kombit.Samples.CH.WebsiteDemo/EmergencyAssets/scenarios.js). See [technical setup](emergency-access-technical-setup.md) and [verification evidence](emergency-access-verification.md).
