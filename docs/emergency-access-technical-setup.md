# Emergency access PoC: setup guide

This guide explains how to configure, deploy and demonstrate emergency access. The app uses the improved UI, signs users in through Identify, and saves emergency-access information in SQLite.

| Application | Address |
|---|---|
| Service provider (SP), the demo app | [https://saml-sp-emergency-01.anyid.eu/](https://saml-sp-emergency-01.anyid.eu/) |
| Identify, the login service | [https://n2adgangsstyringsw.anyid.eu/](https://n2adgangsstyringsw.anyid.eu/) |

Updated November 11, 2026. YubiKey registration, emergency login and automatic renewal were verified in the development environment. The addresses above are the deployment targets; the recorded tests do not represent a separate test of those addresses. Detailed results are in the [verification record](emergency-access-verification.md).

## 1. What the demo provides

Users first sign in normally through Identify. They can then prepare emergency access using a YubiKey or another supported passkey.

During setup, Identify issues a **Passticket**: a time-limited record of the user's access, linked to their registered key. The app uses it to grant limited access when normal login is unavailable. The YubiKey's private key stays on the YubiKey.

After each fresh normal login, the app automatically renews one eligible key associated with the current browser. Renewal does not ask the user to register the key again, enter its PIN or touch it. Refreshing My Page does not trigger another renewal.

Emergency login still requires the user's passkey confirmation. It grants limited access for up to eight hours, ending earlier if the Passticket expires. The demo's outage scenario simulates normal login being unavailable; the emergency authentication itself is real.

## 2. Before you start

The SP needs:

- Windows and IIS, with a 64-bit application pool using one worker process.
- .NET Framework 4.8 and Visual Studio Web Application build tools.
- A trusted HTTPS certificate for `saml-sp-emergency-01.anyid.eu`.
- Edge or another browser that supports passkeys, plus a YubiKey for the hardware-key demonstration.
- Working normal SAML login through Identify.

The Identify development branch supports the emergency enrollment and renewal APIs used by this PoC. Identify must have the matching emergency client configuration in place before SP setup begins. See the [configuration reference](../README-emergency.md) for the detailed settings.

Confirm normal login works before testing emergency setup. The SP and Identify must agree on their SAML settings and certificates. Keep signature validation enabled.

## 3. Configure the app

### Login and emergency-access settings

Start from [emergency-settings.example.json](../emergency-settings.example.json). Keep the live settings file outside the website and source repository. The documented settings location is:

```text
C:\ProgramData\SafewhereSamples\SamlEmergency\emergency-settings.json
```

Match these settings to the deployed environment:

| Setting | What to enter |
|---|---|
| `NormalSamlIssuer` | The exact SAML issuer configured in Identify. Do not assume it is the same as the website address. |
| `IssuerRuntimeUrl` | The HTTPS Runtime API address for `n2adgangsstyringsw.anyid.eu`, including its actual application path and a final `/`. |
| `EmergencyIssuer`, `Audience` | The emergency issuer and audience agreed with the Identify client configuration. |
| `Origin` | `https://saml-sp-emergency-01.anyid.eu` |
| `RpId` | `saml-sp-emergency-01.anyid.eu` |
| `ApiKey` | The shared backend API key configured for this SP in Identify. |
| `EncryptionKeyId` and private key file | The SP encryption key matching the public key registered in Identify. |
| `InitialSigningKeysFile` | The trusted Identify emergency signing keys used to check Passtickets. |

In Web.config, enable the feature with `EmergencyCredential.Enabled` and point `EmergencyCredential.SettingsFile` to the external JSON file. Set `EmergencyCredential.Authenticator` to `any` so Edge can offer a YubiKey alongside other supported passkey options.

For a new installation, use `New-EmergencyKey.ps1` and `Set-EmergencyMachineKey.ps1` as described in the configuration reference. Keep the existing protection keys when updating an installation. The app needs those keys to read its saved information after a restart. Keep API keys and private key files out of browser assets and source control.

### Choose the SQLite folder

Set the same absolute folder in both places:

- `StateDirectory` in the external JSON settings.
- `EmergencyCredential.StateDirectory` in Web.config.

For example:

```text
C:\ProgramData\SafewhereSamples\SamlEmergency\state
```

The app creates `emergency.db` and its database tables automatically when it starts. No database installation or manual SQL commands are needed.

The folder must be outside the website and repository. Give the IIS application-pool identity Modify permission. The deployment script creates the folder and grants this permission for a pool using ApplicationPoolIdentity. If the pool uses a custom service account, provision its folder permissions separately.

An ordinary app restart keeps the database. A demo deployment deliberately clears the SP's previous emergency data, so users must prepare emergency access again. There is no old-data migration.

## 4. Build and deploy

### Build and run the checks

Open a Visual Studio developer PowerShell at the repository root. Replace `<repository-root>` with the full repository path. The empty `PostBuildEvent` prevents the historical deployment-copy step from running.

```powershell
MSBuild.exe .\Kombit.Samples.CH.WebsiteDemo\Kombit.Samples.CH.WebsiteDemo.csproj /restore /nodeReuse:false /maxCpuCount:1 /p:UseSharedCompilation=false /p:PostBuildEvent= /p:SolutionDir="<repository-root>\"
MSBuild.exe .\Kombit.Samples.CH.Emergency.Tests\Kombit.Samples.CH.Emergency.Tests.csproj /restore /nodeReuse:false /maxCpuCount:1 /p:UseSharedCompilation=false
.\Kombit.Samples.CH.Emergency.Tests\bin\Debug\net48\Kombit.Samples.CH.Emergency.Tests.exe --report-trx
node --test Kombit.Samples.CH.Emergency.Tests/*.test.cjs
```

Run the Windows tests under a loaded user profile because they use Windows data protection. The recorded build passed with existing IdentityModel and legacy analysis warnings; those warnings remain outside this UI and SQLite change.

The website build includes the SQLite managed libraries and the 64-bit native `e_sqlite3.dll`. Deploy the complete built `bin` folder, including the existing `libsodium.dll`. The deployment script adds the required SQLite assembly redirect to the live Web.config.

### Update the existing IIS website

The script updates an existing, configured IIS installation. The site, HTTPS binding, normal application pages, images and Identify connection must already be present.

Run from the repository root in **elevated Windows PowerShell**:

```powershell
# This deliberately clears the SP's previous emergency demo data.
.\Deploy-Demo.ps1 -SiteName '<existing-SP-IIS-site-name>'

# Open the app to trigger startup and automatic database creation.
Invoke-WebRequest -UseBasicParsing 'https://saml-sp-emergency-01.anyid.eu/LoginOptions.aspx'
```

Use the actual IIS site name bound to `saml-sp-emergency-01.anyid.eu`; it may differ from the hostname. The script reads the website location from IIS. Its default build source is `Kombit.Samples.CH.WebsiteDemo`; use `-ProjectDirectory` if the built source is elsewhere.

The script stops the application pool, copies the updated pages, emergency assets and DLLs, checks the copies, clears the named SP database/state files and restarts the pool. It preserves environment settings and encryption keys. The first app request creates a fresh SQLite database. Copying files manually does not perform this reset.

If deployment fails after stopping the pool, the pool remains stopped. Correct the reported problem and rerun the deployment. Do not use the deployment script just to restart the app, because it clears demo data.

### Prepare for repeated demonstrations

Resetting the SP does not remove registrations from Identify or credentials from the YubiKey. Identify defaults to two active or pending registrations per user and SP client. Old registrations can therefore prevent a new setup after redeployment.

If this happens, an administrator should identify the obsolete registrations for that demo user and SP client and revoke them through Identify's authenticated `POST emergency/revocations` API, supplying one `binding_id` per request. Keep the cleanup limited to the intended demo registrations. Then sign in normally again before retrying setup. Do not delete Identify's state file to clear registrations.

## 5. Walk through the feature

### Normal login and YubiKey setup

1. Open [My Page](https://saml-sp-emergency-01.anyid.eu/MyPage.aspx).
2. Select Identify and complete normal login with the configured idpdemo provider. An existing Identify session may sign you in automatically.
3. On My Page, choose **Set up emergency access** and follow the dialog.
4. Select **Confirm and set up**. In Edge choose **Security key**, enter the YubiKey PIN privately if requested, and touch the key.
5. Confirm that the app displays **Emergency access is ready**. Open **Manage keys** to check the active key and expiry.

Opening or minimising the setup dialog does not register a key. Registration starts only when the user confirms setup.

### Emergency login

1. Open **Scenarios → Emergency login → Emergency with a key**. This ends the normal SP session and opens the emergency-login flow.
2. Select **Emergency login** and confirm with the registered YubiKey.
3. Confirm that the emergency page displays **Limited access** and a session end time.

The app checks the key locally for emergency login. The information shown comes from the user's previously prepared access, rather than a new normal login.

### Automatic renewal

1. From the emergency page, choose **Sign out locally → Normal login**.
2. Complete normal Identify login. The Normal login link targets My Page and sends unauthenticated users through the normal login handler.
3. The app briefly displays the completion page while refreshing emergency access, then returns to My Page.
4. Open **Manage keys**. Confirm that the same browser key has a later expiry and that no extra YubiKey PIN/touch was needed for renewal.

Use the same browser profile throughout this walkthrough. The browser remembers which registered key to renew. Clearing browser data or closing an InPrivate session can remove that association. Renewal applies to one eligible key in that browser, rather than every key on the account.

## 6. Verified results

The November 11, 2026 development-environment walkthrough completed all three main steps with SQLite. Times below use Asia/Saigon unless marked UTC.

| Check | Result |
|---|---|
| First startup | SQLite was created automatically and passed its integrity check. |
| YubiKey setup | One active key was registered; its initial expiry was December 11 at 11:57:15. |
| Emergency login | YubiKey confirmation opened the limited-access page. The session end was `2026-11-11 12:58:59Z`. |
| Normal login and renewal | The same key's expiry advanced to December 11 at 11:59:47 without another passkey confirmation. Identify accepted the renewal request. |
| Saved state | The final SQLite integrity check passed, and the emergency session was removed after local sign-out. |
| Automated checks | 168 .NET tests and all six JavaScript test files passed. The web build passed. |

Before this successful run, two obsolete Identify registrations for the demo user were revoked through the supported API. Both revocations were confirmed before the new YubiKey was registered.

See the [emergency-login screenshot](../TestResults/visual/sqlite-emergency-success.jpg), [renewal screenshot](../TestResults/visual/sqlite-renewal-success.jpg) and [verification record](emergency-access-verification.md) for supporting evidence and broader test coverage.

## 7. Common problems

| Problem | What to check |
|---|---|
| Edge does not offer the YubiKey | Check `EmergencyCredential.Authenticator=any`, plug in the key and choose Security key in the browser prompt. Confirm that HTTPS is trusted. |
| Setup fails after a fresh deployment | Check for obsolete Identify registrations reaching the key limit. Revoke only the intended demo registrations, then obtain a fresh normal login. |
| The app asks for a new normal login | Setup or renewal may already have used the previous login opportunity, or the app may have restarted. Sign in normally again. |
| Renewal does not happen | Use the same browser profile and check that its prepared key is still active. Refreshing My Page alone does not renew it. |
| SQLite cannot be created or opened | Check that the two folder settings match, the app-pool account has Modify permission, and the full 64-bit SQLite dependencies were deployed. |
| Renewal fails while normal login succeeds | Normal access remains available. Review the error reference and try again after a fresh normal login rather than repeatedly submitting the same request. |

For support, record the time, action, error message and reference ID. Keep PINs, API keys, Passtickets and personal claims out of support reports. Emergency access remains a demo with limited permissions; use normal login when it is available.
