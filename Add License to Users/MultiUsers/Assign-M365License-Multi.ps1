<#
.SYNOPSIS
    Assigns a Microsoft 365 license to one or multiple users.
.DESCRIPTION
    This script connects to Microsoft Graph and assigns a specified license to multiple users.
    Supports input via CSV file, text file, or direct array input.
    Microsoft 365 Business Premium SKU is 'SPB'.
.PARAMETER UserPrincipalNames
    Array of User Principal Names, e.g., @("user1@contoso.com", "user2@contoso.com")
.PARAMETER CsvPath
    Path to a CSV file containing user UPNs. Column name must be 'UserPrincipalName'.
.PARAMETER TxtPath
    Path to a text file with one UPN per line.
.PARAMETER SkuPartNumber
    SkuPartNumber of the license. Defaults to 'SPB' (Microsoft 365 Business Premium).
.PARAMETER UsageLocation
    Default usage location to set if missing. Defaults to 'US'.
.EXAMPLE
    .\Assign-M365License-Multi.ps1 -UserPrincipalNames @("john@contoso.com", "jane@contoso.com")
    Assigns Business Premium license to two users.
.EXAMPLE
    .\Assign-M365License-Multi.ps1 -CsvPath "C:\Users.csv" -SkuPartNumber "ENTERPRISEPACK"
    Assigns E3 licenses to all users in the CSV file.
.EXAMPLE
    .\Assign-M365License-Multi.ps1 -TxtPath "C:\Users.txt" -UsageLocation "GB"
    Assigns Business Premium licenses with UsageLocation set to 'GB'.
#>

param(
    [Parameter(ParameterSetName = "Array")]
    [string[]]$UserPrincipalNames,

    [Parameter(ParameterSetName = "CSV")]
    [string]$CsvPath,

    [Parameter(ParameterSetName = "TXT")]
    [string]$TxtPath,

    [string]$SkuPartNumber = "SPB",
    [string]$UsageLocation = "US"
)

# --- Helper Function to Get Users from Input ---
function Get-UsersFromInput {
    if ($UserPrincipalNames) {
        Write-Host "Using array input with $($UserPrincipalNames.Count) user(s)." -ForegroundColor Cyan
        return $UserPrincipalNames
    }
    elseif ($CsvPath) {
        Write-Host "Reading users from CSV: $CsvPath" -ForegroundColor Cyan
        if (-not (Test-Path $CsvPath)) {
            Write-Error "CSV file not found: $CsvPath"
            exit 1
        }
        $csvData = Import-Csv -Path $CsvPath
        $upns = $csvData | Where-Object { $_.UserPrincipalName } | ForEach-Object { $_.UserPrincipalName.Trim() }
        Write-Host "Found $($upns.Count) user(s) in CSV." -ForegroundColor Cyan
        return $upns
    }
    elseif ($TxtPath) {
        Write-Host "Reading users from TXT: $TxtPath" -ForegroundColor Cyan
        if (-not (Test-Path $TxtPath)) {
            Write-Error "Text file not found: $TxtPath"
            exit 1
        }
        $upns = Get-Content -Path $TxtPath | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() }
        Write-Host "Found $($upns.Count) user(s) in TXT." -ForegroundColor Cyan
        return $upns
    }
    else {
        Write-Error "No user input provided. Use -UserPrincipalNames, -CsvPath, or -TxtPath."
        exit 1
    }
}

# --- Connect to Microsoft Graph ---
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.ReadWrite.All", "Organization.Read.All" -ErrorAction Stop

# --- Get the License SKU ---
Write-Host "Looking up license SKU for '$SkuPartNumber'..." -ForegroundColor Cyan
$sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $SkuPartNumber }

if (-not $sku) {
    Write-Error "License SKU '$SkuPartNumber' not found in your tenant."
    Write-Host "Available SKUs:" -ForegroundColor Yellow
    Get-MgSubscribedSku -All | Select-Object SkuPartNumber, SkuId | Format-Table
    Disconnect-MgGraph
    exit 1
}

# --- Get List of Users ---
$upns = Get-UsersFromInput
$totalUsers = $upns.Count
$successCount = 0
$failedCount = 0
$failedUsers = @()

Write-Host "Processing $totalUsers user(s)..." -ForegroundColor Magenta
Write-Host ("=" * 60) -ForegroundColor Gray

# --- Process Each User ---
$counter = 0
foreach ($upn in $upns) {
    $counter++
    Write-Host "[$counter/$totalUsers] Processing: $upn" -ForegroundColor Yellow
    
    try {
        # --- Check if user exists ---
        $user = Get-MgUser -UserId $upn -Property Id, UserPrincipalName, UsageLocation -ErrorAction Stop
        
        if (-not $user) {
            Write-Host "  ❌ User not found: $upn" -ForegroundColor Red
            $failedCount++
            $failedUsers += $upn
            continue
        }

        # --- Set UsageLocation if missing ---
        if ([string]::IsNullOrEmpty($user.UsageLocation)) {
            Write-Host "  ⚠️ No UsageLocation. Setting to '$UsageLocation'..." -ForegroundColor Yellow
            Update-MgUser -UserId $user.Id -UsageLocation $UsageLocation -ErrorAction Stop
        } else {
            Write-Host "  ✅ UsageLocation: $($user.UsageLocation)" -ForegroundColor Green
        }

        # --- Check if license already assigned ---
        $userLicenses = Get-MgUserLicenseDetail -UserId $user.Id -ErrorAction Stop
        $alreadyAssigned = $userLicenses | Where-Object { $_.SkuId -eq $sku.SkuId }

        if ($alreadyAssigned) {
            Write-Host "  ℹ️ License already assigned to this user. Skipping." -ForegroundColor Cyan
            $successCount++
            continue
        }

        # --- Assign the license ---
        Write-Host "  📝 Assigning license..." -ForegroundColor Yellow
        Set-MgUserLicense -UserId $user.Id `
            -AddLicenses @(@{SkuId = $sku.SkuId}) `
            -RemoveLicenses @() `
            -ErrorAction Stop
        
        Write-Host "  ✅ License assigned successfully!" -ForegroundColor Green
        $successCount++
        
    } catch {
        Write-Host "  ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
        $failedCount++
        $failedUsers += $upn
    }
    
    Write-Host ("-" * 60) -ForegroundColor Gray
}

# --- Summary ---
Write-Host ("=" * 60) -ForegroundColor Gray
Write-Host "📊 SUMMARY" -ForegroundColor Magenta
Write-Host "  Total Users Processed: $totalUsers" -ForegroundColor White
Write-Host "  ✅ Successful: $successCount" -ForegroundColor Green
Write-Host "  ❌ Failed: $failedCount" -ForegroundColor Red

if ($failedUsers) {
    Write-Host "`nFailed Users:" -ForegroundColor Red
    $failedUsers | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

# --- Disconnect ---
Disconnect-MgGraph
Write-Host "`nDisconnected from Microsoft Graph." -ForegroundColor Cyan