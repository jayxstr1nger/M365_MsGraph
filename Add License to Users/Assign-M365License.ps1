<#
.SYNOPSIS
    Assigns a Microsoft 365 license to a user.
.DESCRIPTION
    This script connects to Microsoft Graph and assigns a specified license to a user.
    The SKU for Microsoft 365 Business Premium is 'SPB'.
.PARAMETER UserPrincipalName
    The User Principal Name (UPN) of the user, e.g., user@contoso.com.
.PARAMETER SkuPartNumber
    The SkuPartNumber of the license to assign. Defaults to 'SPB' (Microsoft 365 Business Premium).
.EXAMPLE
    .\Assign-M365License.ps1 -UserPrincipalName "john.doe@contoso.com"
    Assigns a Microsoft 365 Business Premium license to john.doe@contoso.com.
.EXAMPLE
    .\Assign-M365License.ps1 -UserPrincipalName "jane.smith@contoso.com" -SkuPartNumber "ENTERPRISEPACK"
    Assigns an E3 license to jane.smith@contoso.com.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$SkuPartNumber = "SPB" # SPB is the SkuPartNumber for Microsoft 365 Business Premium [citation:12]
)

# --- Step 1: Connect to Microsoft Graph ---
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.ReadWrite.All", "Organization.Read.All" -ErrorAction Stop

# --- Step 2: Get the License SKU ---
Write-Host "Looking up license SKU for '$SkuPartNumber'..." -ForegroundColor Cyan
$sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $SkuPartNumber }

if (-not $sku) {
    Write-Error "License SKU with SkuPartNumber '$SkuPartNumber' not found in your tenant."
    Write-Host "Available SKUs in your tenant:" -ForegroundColor Yellow
    Get-MgSubscribedSku -All | Select-Object SkuPartNumber, SkuId | Format-Table
    Disconnect-MgGraph
    exit 1
}

# --- Step 3: Check if the user has a UsageLocation set ---
Write-Host "Checking UsageLocation for user '$UserPrincipalName'..." -ForegroundColor Cyan
$user = Get-MgUser -UserId $UserPrincipalName -Property Id, UserPrincipalName, UsageLocation

if (-not $user) {
    Write-Error "User '$UserPrincipalName' not found."
    Disconnect-MgGraph
    exit 1
}

if ([string]::IsNullOrEmpty($user.UsageLocation)) {
    Write-Host "Warning: User '$UserPrincipalName' has no UsageLocation set. Setting to 'US'..." -ForegroundColor Yellow
    Update-MgUser -UserId $user.Id -UsageLocation "US"
    Write-Host "UsageLocation set to 'US'." -ForegroundColor Green
}

# --- Step 4: Assign the license ---
Write-Host "Assigning license '$SkuPartNumber' to user '$UserPrincipalName'..." -ForegroundColor Cyan

# Note: The -AddLicenses parameter requires an array of license objects.
# The -RemoveLicenses parameter must be an empty array @() [citation:7][citation:8].
Set-MgUserLicense -UserId $user.Id `
    -AddLicenses @(@{SkuId = $sku.SkuId}) `
    -RemoveLicenses @() `
    -ErrorAction Stop

Write-Host "License '$SkuPartNumber' successfully assigned to '$UserPrincipalName'." -ForegroundColor Green

# --- Step 5: Disconnect ---
Disconnect-MgGraph
Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan