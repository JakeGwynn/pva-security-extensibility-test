#Requires -Version 5.1

<#
.SYNOPSIS
    Calls the Power Virtual Agents securityExtensibility/test API against every Power Platform
    environment in the tenant.

.DESCRIPTION
    Authenticates with an Azure AD app via the OAuth2 device code flow (delegated permissions),
    retrieves all environments by calling the Business Application Platform (BAP) REST API
    directly (so it works in both Windows PowerShell 5.1 and PowerShell 7+), constructs each
    environment's PowerVirtualAgents runtime endpoint from the environment id, and POSTs the
    supplied { endpoint, appId } payload to:
        {pvaEndpoint}/powervirtualagents/api/securityExtensibility/test?api-version=2022-03-01-preview

.PARAMETER Endpoint
    The endpoint URL passed in the request body (the security extensibility endpoint to test).

.PARAMETER AppId
    The application (client) ID passed in the request body.

.PARAMETER ApiVersion
    API version query parameter. Defaults to 2022-03-01-preview.

.PARAMETER EnvironmentNameFilter
    Optional wildcard filter applied to the environment DisplayName to limit which environments
    are processed.

.PARAMETER TenantId
    Azure AD tenant id used for authentication. Required (no default).

.PARAMETER ClientId
    Azure AD app (client) id used for delegated authentication. The app must be configured as a
    public client (mobile/desktop) and have the required delegated permissions for BAP and PVA
    APIs (e.g. PowerVirtualAgents.AdminActions.Invoke). Required (no default).

.EXAMPLE
    .\Invoke-PvaSecurityExtensibilityTestAllEnvironments.ps1 `
        -Endpoint "https://test.example.com" `
        -AppId    "00000000-0000-0000-0000-000000000000" `
        -TenantId "00000000-0000-0000-0000-000000000000" `
        -ClientId "00000000-0000-0000-0000-000000000000"

.NOTES
    Author: Jake Gwynn
    Prerequisites:
        - Signed-in user must have Power Platform admin rights and consent to the required
          delegated permissions (e.g. PowerVirtualAgents.AdminActions.Invoke /
          CopilotStudio.AdminActions.Invoke).
        - The app registration must allow public client (device code) flows.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Endpoint,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$AppId,

    [Parameter(Mandatory = $false)]
    [string]$ApiVersion = "2022-03-01-preview",

    [Parameter(Mandatory = $false)]
    [string]$EnvironmentNameFilter,

    # Azure AD tenant + app registration to authenticate with (delegated, device-code flow).
    # See README.md for the required app permissions and configuration.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId
)

$ErrorActionPreference = 'Stop'

# Ensure modern TLS for older Windows PowerShell hosts (BAP/PVA endpoints require TLS 1.2+).
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
}
catch {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    # Use Write-Host so messages don't pollute the function return stream.
    Write-Host $Message -ForegroundColor $Color
}

function Get-PvaEndpoint {
    param($Environment)

    # Build the PVA host from the environment id, e.g.
    #   1af807c9-8aef-ee26-8a49-8f001a23ce1b
    #     -> 1af807c98aefee268a498f001a23ce.1b.environment.api.powerplatform.com
    $envId = $Environment.name
    if ([string]::IsNullOrWhiteSpace($envId)) { return $null }

    $stripped = $envId -replace '-', ''
    if ($stripped.Length -lt 3) { return $null }

    $hostPrefix = "{0}.{1}" -f $stripped.Substring(0, $stripped.Length - 2), $stripped.Substring($stripped.Length - 2, 2)
    return "https://$hostPrefix.environment.api.powerplatform.com"
}

function Get-AccessTokenForResource {
    param(
        [Parameter(Mandatory)][string]$ResourceUrl,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId
    )

    $scope    = ($ResourceUrl.TrimEnd('/')) + '/.default offline_access'
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    # If we already have a refresh token from a previous call in this session, use it silently.
    if ($script:DelegatedRefreshToken) {
        try {
            $body = @{
                grant_type    = 'refresh_token'
                client_id     = $ClientId
                refresh_token = $script:DelegatedRefreshToken
                scope         = $scope
            }
            $resp = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded'
            if ($resp.refresh_token) { $script:DelegatedRefreshToken = $resp.refresh_token }
            return $resp.access_token
        }
        catch {
            Write-ColorOutput "  Refresh token failed - falling back to interactive sign-in: $($_.Exception.Message)" "DarkYellow"
            $script:DelegatedRefreshToken = $null
        }
    }

    # Device code flow (delegated).
    $devCodeUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $dc = Invoke-RestMethod -Method POST -Uri $devCodeUri -Body @{
        client_id = $ClientId
        scope     = $scope
    } -ContentType 'application/x-www-form-urlencoded'

    Write-ColorOutput "" "White"
    Write-ColorOutput "=== Sign-in required (delegated) ===" "Magenta"
    Write-ColorOutput $dc.message "Yellow"
    Write-ColorOutput "(Resource: $ResourceUrl)" "Gray"

    $expiresAt = (Get-Date).AddSeconds([int]$dc.expires_in)
    $interval  = [int]$dc.interval
    if ($interval -le 0) { $interval = 5 }

    while ((Get-Date) -lt $expiresAt) {
        Start-Sleep -Seconds $interval
        try {
            $resp = Invoke-RestMethod -Method POST -Uri $tokenUri -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $ClientId
                device_code = $dc.device_code
            } -ContentType 'application/x-www-form-urlencoded'

            if ($resp.refresh_token) { $script:DelegatedRefreshToken = $resp.refresh_token }
            return $resp.access_token
        }
        catch {
            $err = $null
            try { $err = ($_.ErrorDetails.Message | ConvertFrom-Json) } catch {}
            switch ($err.error) {
                'authorization_pending' { continue }
                'slow_down'             { $interval += 5; continue }
                default {
                    throw "Device code auth failed: $($err.error) - $($err.error_description)"
                }
            }
        }
    }
    throw "Device code expired before sign-in completed."
}

function Invoke-JsonRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$AccessToken,
        [string]$Body,
        [int]$MaxAttempts = 5
    )

    $headers = @{
        Authorization = "Bearer $AccessToken"
        Accept        = 'application/json'
    }

    $iwrParams = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = $headers
        ErrorAction = 'Stop'
    }
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $iwrParams.SkipHttpErrorCheck = $true
    }
    else {
        $iwrParams.UseBasicParsing = $true
    }
    if ($Body) {
        $iwrParams.Body        = $Body
        $iwrParams.ContentType = 'application/json'
    }

    $attempt    = 0
    $lastError  = $null
    $resp       = $null
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            $resp = Invoke-WebRequest @iwrParams
            $lastError = $null
            break
        }
        catch {
            $lastError = $_
            $msg = $_.Exception.Message
            # Retry only on transport-level failures (TLS handshake, connection reset, etc.).
            $isTransport = $msg -match 'transport stream|underlying connection|connection was closed|reset|forcibly closed|handshake|SSL|TLS|timed? ?out'
            if (-not $isTransport -or $attempt -ge $MaxAttempts) { break }
            $delay = [Math]::Min(8, [Math]::Pow(2, $attempt - 1))
            Write-ColorOutput "  Transport error (attempt $attempt/$MaxAttempts): $msg - retrying in ${delay}s" "DarkYellow"
            Start-Sleep -Seconds $delay
        }
    }

    if ($lastError) {
        # PS 5.1 throws on non-2xx; pull body out of the WebException response.
        $ex   = $lastError.Exception
        $code = $null
        $body = $null
        $hdrText = '<no response>'
        if ($ex.Response) {
            try { $code = [int]$ex.Response.StatusCode } catch {}
            try {
                $stream = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $body   = $reader.ReadToEnd()
                $reader.Dispose()
            } catch {}
            try {
                $hdrText = ($ex.Response.Headers | ForEach-Object { "$_`: $($ex.Response.Headers[$_])" }) -join "`n"
            } catch {}
        }
        $codeText = if ($code) { $code } else { 'n/a' }
        $bodyText = if ([string]::IsNullOrWhiteSpace($body)) { '<empty body>' } else { $body.Trim() }
        throw @"
HTTP $codeText from $Method $Uri (after $attempt attempt(s))
$($ex.Message)
--- Response headers ---
$hdrText
--- Response body ---
$bodyText
"@
    }

    $statusInt = [int]$resp.StatusCode
    if ($statusInt -lt 200 -or $statusInt -ge 300) {
        $hdrText  = ($resp.Headers.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value -join ', ')" }) -join "`n"
        $bodyText = if ([string]::IsNullOrWhiteSpace($resp.Content)) { '<empty body>' } else { $resp.Content.Trim() }
        throw @"
HTTP $statusInt from $Method $Uri
--- Response headers ---
$hdrText
--- Response body ---
$bodyText
"@
    }

    if ([string]::IsNullOrWhiteSpace($resp.Content)) { return $null }
    try   { return $resp.Content | ConvertFrom-Json -ErrorAction Stop }
    catch { return $resp.Content }
}

function Get-AllPowerPlatformEnvironments {
    param([Parameter(Mandatory)][string]$BapAccessToken)

    $uri = 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?$expand=permissions&api-version=2020-10-01'
    $all = New-Object System.Collections.Generic.List[object]
    while ($uri) {
        $resp = Invoke-JsonRequest -Method GET -Uri $uri -AccessToken $BapAccessToken
        if ($resp.value) { $all.AddRange([object[]]$resp.value) }
        $uri = $resp.nextLink
    }
    return $all
}

function Invoke-PvaSecurityExtensibilityTest {
    param(
        [string]$PvaEndpoint,
        [string]$AccessToken,
        [string]$ApiVersion,
        [string]$BodyEndpoint,
        [string]$BodyAppId
    )

    $uri  = "$PvaEndpoint/powervirtualagents/api/securityExtensibility/test?api-version=$ApiVersion"
    $body = @{ endpoint = $BodyEndpoint; appId = $BodyAppId } | ConvertTo-Json -Compress
    Write-ColorOutput "  POST $uri" "Gray"
    return Invoke-JsonRequest -Method POST -Uri $uri -AccessToken $AccessToken -Body $body
}

# --- Main ---------------------------------------------------------------

Write-ColorOutput "=== PVA Security Extensibility Test - All Environments ===" "Magenta"
Write-ColorOutput "Endpoint: $Endpoint" "White"
Write-ColorOutput "AppId   : $AppId"  "White"
Write-ColorOutput ""

Write-ColorOutput "Acquiring access token for BAP API (https://api.bap.microsoft.com/) ..." "Cyan"
$bapToken = Get-AccessTokenForResource -ResourceUrl "https://api.bap.microsoft.com/" `
    -TenantId $TenantId -ClientId $ClientId

Write-ColorOutput "Acquiring access token for Power Platform API (https://api.powerplatform.com/) ..." "Cyan"
$accessToken = Get-AccessTokenForResource -ResourceUrl "https://api.powerplatform.com/" `
    -TenantId $TenantId -ClientId $ClientId

Write-ColorOutput "Retrieving environments via BAP REST API..." "Cyan"
$environments = Get-AllPowerPlatformEnvironments -BapAccessToken $bapToken
if ($EnvironmentNameFilter) {
    $environments = $environments | Where-Object { $_.properties.displayName -like $EnvironmentNameFilter }
}
Write-ColorOutput "Found $($environments.Count) environment(s) to process." "Green"

$results = New-Object System.Collections.Generic.List[object]
$successCount = 0
$failureCount = 0
$skippedCount = 0

foreach ($env in $environments) {
    $envDisplay = $env.properties.displayName
    $envName    = $env.name
    Write-ColorOutput ""
    Write-ColorOutput "Environment: $envDisplay ($envName)" "White"

    $pvaEndpoint = Get-PvaEndpoint -Environment $env
    if (-not $pvaEndpoint) {
        Write-ColorOutput "  No PowerVirtualAgents runtime endpoint - skipping." "Yellow"
        $skippedCount++
        $results.Add([pscustomobject]@{
            Environment = $envDisplay
            EnvironmentName = $envName
            PvaEndpoint = $null
            Status = 'Skipped'
            Response = $null
            Error = 'No PVA runtime endpoint'
        }) | Out-Null
        continue
    }

    if (-not $PSCmdlet.ShouldProcess($envDisplay, "POST securityExtensibility/test")) {
        $skippedCount++
        continue
    }

    try {
        $response = Invoke-PvaSecurityExtensibilityTest `
            -PvaEndpoint $pvaEndpoint `
            -AccessToken $accessToken `
            -ApiVersion  $ApiVersion `
            -BodyEndpoint $Endpoint `
            -BodyAppId    $AppId

        Write-ColorOutput "  Success" "Green"
        $successCount++
        $results.Add([pscustomobject]@{
            Environment = $envDisplay
            EnvironmentName = $envName
            PvaEndpoint = $pvaEndpoint
            Status = 'Success'
            Response = $response
            Error = $null
        }) | Out-Null
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-ColorOutput "  Failed: $errMsg" "Red"
        $failureCount++
        $results.Add([pscustomobject]@{
            Environment = $envDisplay
            EnvironmentName = $envName
            PvaEndpoint = $pvaEndpoint
            Status = 'Failed'
            Response = $null
            Error = $errMsg
        }) | Out-Null
    }
}

Write-ColorOutput ""
Write-ColorOutput "=== SUMMARY ===" "Magenta"
Write-ColorOutput "Total    : $($environments.Count)" "White"
Write-ColorOutput "Success  : $successCount" "Green"
Write-ColorOutput "Failed   : $failureCount" "Red"
Write-ColorOutput "Skipped  : $skippedCount" "Yellow"

return $results
