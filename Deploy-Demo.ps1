#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$SiteName = 'kombitspnew.safewhere.local',
    [string]$ProjectDirectory = (Join-Path $PSScriptRoot 'Kombit.Samples.CH.WebsiteDemo')
)
$ErrorActionPreference = 'Stop'
Add-Type -Path "$env:windir\System32\inetsrv\Microsoft.Web.Administration.dll"
$manager = New-Object Microsoft.Web.Administration.ServerManager
try {
    $site = $manager.Sites[$SiteName]
    if (!$site) { throw 'IIS site does not exist.' }
    $app = $site.Applications['/']
    $target = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($app.VirtualDirectories['/'].PhysicalPath)).TrimEnd('\')
    $source = [IO.Path]::GetFullPath($ProjectDirectory).TrimEnd('\')
    if ($source -eq $target) { throw 'Build source must differ from IIS target.' }
    [xml]$config = Get-Content -LiteralPath (Join-Path $target 'Web.config')
    $settingsFile = ($config.configuration.appSettings.add | Where-Object key -eq 'EmergencyCredential.SettingsFile').value
    $stateSetting = ($config.configuration.appSettings.add | Where-Object key -eq 'EmergencyCredential.StateDirectory').value
    $settings = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
    $state = [IO.Path]::GetFullPath($stateSetting).TrimEnd('\')
    if ($state -ne [IO.Path]::GetFullPath($settings.StateDirectory).TrimEnd('\') -or
        $state.StartsWith($target + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $state -eq $target -or $state -eq [IO.Path]::GetPathRoot($state).TrimEnd('\') -or $state.StartsWith('\\')) {
        throw 'Database folder must match both settings and be an external local directory.'
    }
    $files = @('sp.Master','MyPage.aspx','LoginOptions.aspx','Emergency.Master','EmergencyComplete.aspx')
    $files += @(Get-ChildItem -LiteralPath (Join-Path $source 'EmergencyAssets') -File | ForEach-Object { 'EmergencyAssets\' + $_.Name })
    $files += @(Get-ChildItem -LiteralPath (Join-Path $source 'bin') -Filter '*.dll' -File | ForEach-Object { 'bin\' + $_.Name })
    foreach ($required in @('e_sqlite3.dll','Microsoft.Data.Sqlite.dll','SQLitePCLRaw.core.dll','SQLitePCLRaw.batteries_v2.dll','SQLitePCLRaw.provider.dynamic_cdecl.dll')) {
        if (!(Test-Path -LiteralPath (Join-Path $source ('bin\' + $required)))) { throw "Missing SQLite dependency: $required" }
    }
    foreach ($relative in $files) {
        if (!(Test-Path -LiteralPath (Join-Path $source $relative) -PathType Leaf)) { throw "Missing build file: $relative" }
    }
    $pool = $manager.ApplicationPools[$app.ApplicationPoolName]
    if ($pool.State -ne 'Stopped') { $pool.Stop() | Out-Null }
    $deadline = (Get-Date).AddSeconds(40)
    do {
        Start-Sleep -Milliseconds 300
        $check = New-Object Microsoft.Web.Administration.ServerManager
        try { $running = @($check.WorkerProcesses | Where-Object AppPoolName -eq $pool.Name).Count }
        finally { $check.Dispose() }
        if ((Get-Date) -gt $deadline) { throw 'IIS worker did not stop.' }
    } while ($running -gt 0)
    # Only the named SP database files are reset. No CH2 files or private keys are touched.
    New-Item -ItemType Directory -Path $state -Force | Out-Null
    if ($pool.ProcessModel.IdentityType -eq 'ApplicationPoolIdentity') {
        $acl = Get-Acl -LiteralPath $state
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("IIS AppPool\$($pool.Name)", 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        Set-Acl -LiteralPath $state -AclObject $acl
    }
    foreach ($relative in $files) {
        $destination = Join-Path $target $relative
        New-Item -ItemType Directory -Path (Split-Path $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $source $relative) -Destination $destination -Force
        if ((Get-FileHash -LiteralPath $destination).Hash -ne (Get-FileHash -LiteralPath (Join-Path $source $relative)).Hash) { throw "Copy failed: $relative" }
    }
    foreach ($name in @('emergency.db','emergency.db-journal','emergency.db-wal','emergency.db-shm','registry.bin','initialized','support-disabled')) {
        $file = Join-Path $state $name
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file -Force }
    }
    # Merge only this dependency redirect; retain environment-specific secrets/settings.
    $ns = New-Object System.Xml.XmlNamespaceManager($config.NameTable)
    $ns.AddNamespace('asm', 'urn:schemas-microsoft-com:asm.v1')
    $bindings = $config.SelectSingleNode('/configuration/runtime/asm:assemblyBinding', $ns)
    if (!$bindings) { throw 'Missing assembly binding configuration.' }
    $existing = $bindings.SelectSingleNode("asm:dependentAssembly[asm:assemblyIdentity/@name='SQLitePCLRaw.core']", $ns)
    if ($existing) { $bindings.RemoveChild($existing) | Out-Null }
    $fragment = $config.CreateDocumentFragment()
    $fragment.InnerXml = '<dependentAssembly xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="SQLitePCLRaw.core" publicKeyToken="1488e028ca7ab535" culture="neutral"/><bindingRedirect oldVersion="0.0.0.0-2.1.12.3116" newVersion="2.1.12.3116"/></dependentAssembly>'
    $bindings.AppendChild($fragment) | Out-Null
    $config.Save((Join-Path $target 'Web.config'))
    $pool.Start() | Out-Null
    Write-Output "Deployed $SiteName. SP database reset; application startup creates $state\emergency.db."
} finally {
    # On deployment failure leave the pool stopped instead of serving a partial package.
    $manager.Dispose()
}
