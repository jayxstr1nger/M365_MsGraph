<#
.SYNOPSIS
    Creates multiple users in Microsoft Entra ID (Azure AD) from a CSV file.
.DESCRIPTION
    This script reads user data from a CSV file and creates users in Microsoft Entra ID
    using Microsoft Graph. It handles duplicate detection, error handling, and reporting.
.PARAMETER CsvPath
    Path to the CSV file containing user data.
.PARAMETER DefaultPassword
    Default password for new users. If not provided, a random password will be generated.
.PARAMETER ForcePasswordChange
    Forces users to change password on first sign-in. Default is $true.
.PARAMETER UsageLocation
    Default usage location for licenses. Defaults to 'US'.
.PARAMETER DryRun
    Simulates the creation without actually creating users.
.EXAMPLE
    .\Create-BulkUsers.ps1 -CsvPath "C:\NewUsers.csv"
.EXAMPLE
    .\Create-BulkUsers.ps1 -CsvPath "C:\NewUsers.csv" -DefaultPassword "TempP@ssw0rd!" -ForcePasswordChange $true
.EXAMPLE
    .\Create-BulkUsers.ps1 -CsvPath "C:\NewUsers.csv" -DryRun
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [SecureString]$DefaultPassword,
    
    [Parameter(Mandatory = $false)]
    [bool]$ForcePasswordChange = $true,
    
    [Parameter(Mandatory = $false)]
    [string]$UsageLocation = "US",
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

# --- Helper Function: Generate Random Password ---
function New-RandomPassword {
    param([int]$Length = 14)
    
    $specialChars = '!@#$%^&*'
    $characters = "abcdefghkmnpqrstuvwxyzABCDEFGHKLMNPQRSTUVWXYZ123456789$specialChars"
    $password = -join ((1..$Length) | ForEach-Object { $characters[(Get-Random -Maximum $characters.Length)] })
    
    # Ensure at least one uppercase, lowercase, digit, and special character
    $password = $password -replace '^(.{' + ($Length - 4) + '})(.*)$', "`$1A1$($specialChars[0])`$2"
    
    return $password
}

# --- Connect to Microsoft Graph ---
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All" -ErrorAction Stop

# --- Validate CSV File ---
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    Disconnect-MgGraph
    exit 1
}

# --- Read CSV Data ---
Write-Host "Reading CSV file: $CsvPath" -ForegroundColor Cyan
try {
    $users = Import-Csv -Path $CsvPath -ErrorAction Stop
} catch {
    Write-Error "Failed to read CSV: $_"
    Disconnect-MgGraph
    exit 1
}

Write-Host "Found $($users.Count) user(s) to create." -ForegroundColor Cyan

# --- Validate CSV Headers ---
$requiredHeaders = @("FirstName", "LastName", "UserPrincipalName", "DisplayName")
$missingHeaders = $requiredHeaders | Where-Object { $_ -notin $users[0].PSObject.Properties.Name }

if ($missingHeaders) {
    Write-Error "CSV is missing required headers: $($missingHeaders -join ', ')"
    Write-Host "Required headers: $($requiredHeaders -join ', ')" -ForegroundColor Yellow
    Write-Host "Optional headers: Department, JobTitle, Office, MobilePhone, UsageLocation" -ForegroundColor Yellow
    Disconnect-MgGraph
    exit 1
}

# --- Statistics ---
$totalUsers = $users.Count
$successCount = 0
$failedCount = 0
$failedUsers = @()
$createdUsers = @()

Write-Host ("=" * 60) -ForegroundColor Gray

# --- Process Each User ---
$counter = 0
foreach ($user in $users) {
    $counter++
    
    # Skip rows with missing required fields
    if ([string]::IsNullOrWhiteSpace($user.UserPrincipalName) -or 
        [string]::IsNullOrWhiteSpace($user.FirstName) -or 
        [string]::IsNullOrWhiteSpace($user.LastName)) {
        Write-Host "[$counter/$totalUsers] ⚠️ Skipping: Missing required fields for user: $($user.DisplayName)" -ForegroundColor Yellow
        $failedCount++
        $failedUsers += "Row ${counter}: Missing required fields"
        continue
    }
    
    # Build display name if not provided
    if ([string]::IsNullOrWhiteSpace($user.DisplayName)) {
        $user.DisplayName = "$($user.FirstName) $($user.LastName)"
    }
    
    Write-Host "[$counter/$totalUsers] Processing: $($user.UserPrincipalName)" -ForegroundColor Yellow
    
    # --- Check if user already exists ---
    $existingUser = Get-MgUser -UserId $user.UserPrincipalName -ErrorAction SilentlyContinue
    
    if ($existingUser) {
        Write-Host "  ℹ️ User already exists: $($user.UserPrincipalName)" -ForegroundColor Cyan
        $successCount++  # Count as "success" since user exists
        continue
    }
    
    # --- Generate or use default password ---
    if ([string]::IsNullOrWhiteSpace($DefaultPassword)) {
        $password = New-RandomPassword
    } else {
        $password = $DefaultPassword
    }
    
    # --- Prepare user properties ---
    $userParams = @{
        UserPrincipalName = $user.UserPrincipalName
        DisplayName = $user.DisplayName
        GivenName = $user.FirstName
        Surname = $user.LastName
        MailNickname = $user.UserPrincipalName.Split('@')[0]
        AccountEnabled = $true
        PasswordProfile = @{
            Password = $password
            ForceChangePasswordNextSignIn = $ForcePasswordChange
        }
        PasswordPolicies = "DisablePasswordExpiration"
    }
    
    # --- Add optional properties ---
    if ($user.Department) { $userParams.Department = $user.Department }
    if ($user.JobTitle) { $userParams.JobTitle = $user.JobTitle }
    if ($user.Office) { $userParams.OfficeLocation = $user.Office }
    if ($user.MobilePhone) { $userParams.MobilePhone = $user.MobilePhone }
    
    # Set UsageLocation
    $location = if ($user.UsageLocation) { $user.UsageLocation } else { $UsageLocation }
    $userParams.UsageLocation = $location
    
    # --- Create the user (or simulate) ---
    if ($DryRun) {
        Write-Host "  🧪 [DRY RUN] Would create user: $($user.UserPrincipalName)" -ForegroundColor Yellow
        Write-Host "    Password: $password" -ForegroundColor Gray
        $successCount++
        $createdUsers += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName = $user.DisplayName
            Password = $password
            Status = "Dry Run"
        }
    } else {
        try {
            Write-Host "  📝 Creating user..." -ForegroundColor Yellow
            $newUser = New-MgUser @userParams -ErrorAction Stop
            
            Write-Host "  ✅ User created successfully!" -ForegroundColor Green
            $successCount++
            
            $createdUsers += [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                Password = $password
                Status = "Created"
                Id = $newUser.Id
            }
            
        } catch {
            Write-Host "  ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
            $failedCount++
            $failedUsers += "$($user.UserPrincipalName): $($_.Exception.Message)"
        }
    }
    
    Write-Host ("-" * 60) -ForegroundColor Gray
}

# --- Summary ---
Write-Host ("=" * 60) -ForegroundColor Gray
Write-Host "📊 SUMMARY" -ForegroundColor Magenta
Write-Host "  Total Users Processed: $totalUsers" -ForegroundColor White
Write-Host "  ✅ Successful: $successCount" -ForegroundColor Green
Write-Host "  ❌ Failed: $failedCount" -ForegroundColor Red

if ($createdUsers) {
    Write-Host "`n📋 Created Users (with passwords):" -ForegroundColor Cyan
    $createdUsers | Format-Table UserPrincipalName, DisplayName, Status, Password -AutoSize
}

if ($failedUsers) {
    Write-Host "`n❌ Failed Users:" -ForegroundColor Red
    $failedUsers | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

# --- Export results to CSV ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$resultPath = "UserCreation_Results_$timestamp.csv"

if ($createdUsers) {
    $createdUsers | Export-Csv -Path $resultPath -NoTypeInformation
    Write-Host "`n📁 Results exported to: $resultPath" -ForegroundColor Cyan
}

# --- Disconnect ---
Disconnect-MgGraph
Write-Host "`nDisconnected from Microsoft Graph." -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "🧪 This was a DRY RUN. No users were actually created." -ForegroundColor Yellow
}