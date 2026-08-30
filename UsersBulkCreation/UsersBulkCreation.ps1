<#
.SYNOPSIS
    Creates users in Microsoft Entra ID and auto-creates department groups with membership.
.DESCRIPTION
    This script reads user data from a CSV file, creates users in Microsoft Entra ID,
    and automatically creates security groups for each department, adding users to their respective groups.
    UserPrincipalName is automatically generated from GivenName + Surname + Domain.
    EXISTING USERS ARE SKIPPED - they are not created again, but are added to groups.
.PARAMETER CsvPath
    Path to the CSV file containing user data.
.PARAMETER Domain
    Domain to use for UserPrincipalName. Default is 'IntBussMgt.onmicrosoft.com'.
.PARAMETER DefaultPassword
    Default password for new users. If not provided, a random password will be generated.
.PARAMETER ForcePasswordChange
    Forces users to change password on first sign-in. Default is $true.
.PARAMETER UsageLocation
    Default usage location for licenses. Defaults to 'US'.
.PARAMETER DryRun
    Simulates the creation without actually creating users.
.PARAMETER GroupPrefix
    Prefix for group names (e.g., "Department_" creates "Department_IT").
.PARAMETER GroupDescription
    Default description for groups.
.PARAMETER CreateGroupsOnly
    If true, only creates groups without creating users.
.PARAMETER SkipExistingUsers
    If true, skips existing users (does not create them). Default is $true.
.EXAMPLE
    .\Create-BulkUsers-WithGroups.ps1 -CsvPath "users.csv"
.EXAMPLE
    .\Create-BulkUsers-WithGroups.ps1 -CsvPath "users.csv" -SkipExistingUsers $false
.EXAMPLE
    .\Create-BulkUsers-WithGroups.ps1 -CsvPath "users.csv" -DryRun
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [string]$Domain = "IntBussMgt.onmicrosoft.com",
    
    [Parameter(Mandatory = $false)]
    [SecureString]$DefaultPassword,
    
    [Parameter(Mandatory = $false)]
    [bool]$ForcePasswordChange = $true,
    
    [Parameter(Mandatory = $false)]
    [string]$UsageLocation = "US",
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    # --- Group Parameters ---
    [Parameter(Mandatory = $false)]
    [string]$GroupPrefix = "Department_",
    
    [Parameter(Mandatory = $false)]
    [string]$GroupDescription = "Auto-created department group",
    
    [Parameter(Mandatory = $false)]
    [switch]$CreateGroupsOnly,

    # --- Skip Existing Users ---
    [Parameter(Mandatory = $false)]
    [bool]$SkipExistingUsers = $true,

    # --- Default User Parameters ---
    [Parameter(Mandatory = $false)]
    [string]$DisplayName,
    
    [Parameter(Mandatory = $false)]
    [string]$Surname,
    
    [Parameter(Mandatory = $false)]
    [string]$GivenName,
    
    [Parameter(Mandatory = $false)]
    [string]$JobTitle,
    
    [Parameter(Mandatory = $false)]
    [string]$Department,
    
    [Parameter(Mandatory = $false)]
    [bool]$AccountEnabled = $true,
    
    [Parameter(Mandatory = $false)]
    [string]$Country,
    
    [Parameter(Mandatory = $false)]
    [string]$OfficeLocation,
    
    [Parameter(Mandatory = $false)]
    [string]$City,
    
    [Parameter(Mandatory = $false)]
    [string]$MobilePhone,
    
    [Parameter(Mandatory = $false)]
    [string]$License
)

# --- Helper Function: Generate Random Password ---
function New-RandomPassword {
    param([int]$Length = 14)
    
    $specialChars = '!@#$%^&*'
    $characters = "abcdefghkmnpqrstuvwxyzABCDEFGHKLMNPQRSTUVWXYZ123456789$specialChars"
    $password = -join ((1..$Length) | ForEach-Object { $characters[(Get-Random -Maximum $characters.Length)] })
    
    $password = $password -replace '^(.{' + ($Length - 4) + '})(.*)$', "`$1A1$($specialChars[0])`$2"
    
    return $password
}

# --- Helper Function: Generate UserPrincipalName ---
function New-UserPrincipalName {
    param(
        [string]$GivenName,
        [string]$Surname,
        [string]$Domain
    )
    
    $cleanGivenName = $GivenName -replace '[^a-zA-Z0-9]', '' -replace '\s+', '' -replace '^-|-$', ''
    $cleanSurname = $Surname -replace '[^a-zA-Z0-9]', '' -replace '\s+', '' -replace '^-|-$', ''
    
    $upn = "$cleanGivenName.$cleanSurname"
    $upn = $upn -replace '\.\.+', '.'
    $upn = $upn -replace '^\.|\.$', ''
    
    if ([string]::IsNullOrWhiteSpace($upn)) {
        $upn = "user" + (Get-Random -Minimum 1000 -Maximum 9999).ToString()
    }
    
    $upn = "$upn@$Domain"
    return $upn.ToLower()
}

# --- Helper Function: Validate Domain ---
function Test-Domain {
    param([string]$Domain)
    if ($Domain -notmatch '\.') {
        return $false
    }
    return $true
}

# --- Helper Function: Add License to User ---
function Add-LicenseToUser {
    param(
        [string]$UserId,
        [string]$LicenseSku,
        [string]$UsageLocation
    )
    
    if ([string]::IsNullOrWhiteSpace($LicenseSku)) {
        return $true
    }
    
    try {
        $sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $LicenseSku }
        
        if (-not $sku) {
            Write-Host "  ⚠️ License SKU '$LicenseSku' not found. Skipping." -ForegroundColor Yellow
            return $true
        }
        
        Set-MgUserLicense -UserId $UserId `
            -AddLicenses @(@{SkuId = $sku.SkuId}) `
            -RemoveLicenses @() `
            -ErrorAction Stop
        
        Write-Host "  ✅ License assigned successfully!" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "  ⚠️ License assignment failed: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

# --- Helper Function: Create or Get Department Group ---
function Get-CreateDepartmentGroup {
    param(
        [string]$DepartmentName,
        [string]$GroupPrefix,
        [string]$GroupDescription
    )
    
    if ([string]::IsNullOrWhiteSpace($DepartmentName)) {
        return $null
    }
    
    # Clean department name for group display name
    $cleanDept = $DepartmentName.Trim()
    $groupDisplayName = "$GroupPrefix$cleanDept"
    $groupMailNickname = ($groupDisplayName -replace '[^a-zA-Z0-9]', '').ToLower()
    
    # Check if group already exists
    try {
        $existingGroup = Get-MgGroup -Filter "displayName eq '$groupDisplayName'" -ErrorAction SilentlyContinue
        
        if ($existingGroup) {
            Write-Host "  ℹ️ Group already exists: $groupDisplayName" -ForegroundColor Cyan
            return $existingGroup
        }
        
        if ($DryRun) {
            Write-Host "  🧪 [DRY RUN] Would create group: $groupDisplayName" -ForegroundColor Yellow
            return $null
        }
        
        # Create the group
        Write-Host "  📝 Creating group: $groupDisplayName..." -ForegroundColor Yellow
        
        $groupParams = @{
            DisplayName = $groupDisplayName
            MailEnabled = $false
            MailNickname = $groupMailNickname
            SecurityEnabled = $true
            Description = "$GroupDescription - $cleanDept"
        }
        
        $newGroup = New-MgGroup @groupParams -ErrorAction Stop
        
        Write-Host "  ✅ Group created: $groupDisplayName (ID: $($newGroup.Id))" -ForegroundColor Green
        return $newGroup
        
    } catch {
        Write-Host "  ❌ Failed to create group '$groupDisplayName': $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# --- Helper Function: Add User to Group ---
function Add-UserToGroup {
    param(
        [string]$UserId,
        [string]$GroupId
    )
    
    if (-not $UserId -or -not $GroupId) {
        return $false
    }
    
    try {
        # Check if user is already a member
        $isMember = Get-MgGroupMember -GroupId $GroupId -Filter "id eq '$UserId'" -ErrorAction SilentlyContinue
        
        if ($isMember) {
            Write-Host "  ℹ️ User is already a member of the group." -ForegroundColor Cyan
            return $true
        }
        
        if ($DryRun) {
            Write-Host "  🧪 [DRY RUN] Would add user to group." -ForegroundColor Yellow
            return $true
        }
        
        # Add user to group
        New-MgGroupMember -GroupId $GroupId -DirectoryObjectId $UserId -ErrorAction Stop
        Write-Host "  ✅ User added to group!" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "  ❌ Failed to add user to group: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# --- Helper Function: Check if User Exists ---
function Get-ExistingUser {
    param([string]$UserPrincipalName)
    
    # Try multiple methods to find the user
    
    # Method 1: Direct lookup by UserPrincipalName
    try {
        $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction SilentlyContinue
        if ($user) { return $user }
    } catch { }
    
    # Method 2: Filter by userPrincipalName
    try {
        $user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue
        if ($user) { return $user }
    } catch { }
    
    # Method 3: Filter by mail (email attribute)
    try {
        $user = Get-MgUser -Filter "mail eq '$UserPrincipalName'" -ErrorAction SilentlyContinue
        if ($user) { return $user }
    } catch { }
    
    # Method 4: Check by proxyAddresses (smtp:user@domain.com)
    try {
        $user = Get-MgUser -Filter "proxyAddresses/any(c:c eq 'smtp:$UserPrincipalName')" -ErrorAction SilentlyContinue
        if ($user) { return $user }
    } catch { }
    
    # Method 5: Check by otherMail (alternative email)
    try {
        $user = Get-MgUser -Filter "otherMails/any(c:c eq '$UserPrincipalName')" -ErrorAction SilentlyContinue
        if ($user) { return $user }
    } catch { }
    
    return $null
}

<# --- Connect to Microsoft Graph ---
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Organization.Read.All", "Group.ReadWrite.All" -ErrorAction Stop

# Create a secure credential file (run once)
$credential = Get-Credential
$credential | Export-Clixml -Path "C:\Terraform\graph_cred.xml"

# Then use it in your script
$credential = Import-Clixml -Path "C:\Terraform\graph_cred.xml"
Connect-MgGraph -ClientId "3cbdabae-f14c-4e3e-8752-d4150d05f7aa" `
    -TenantId "dfa3a4aa-d956-45fd-9a83-e0ddfd4780ba" `
    -ClientSecret $credential.GetNetworkCredential().Password
#>    

# --- Validate CSV File ---
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    Disconnect-MgGraph
    exit 1
}

# --- Validate Domain ---
if (-not (Test-Domain -Domain $Domain)) {
    Write-Error "Invalid domain format."
    Disconnect-MgGraph
    exit 1
}

Write-Host "Using domain: $Domain" -ForegroundColor Cyan
Write-Host "Skip Existing Users: $SkipExistingUsers" -ForegroundColor Cyan

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

# --- Check CSV Headers (flexible) ---
$headers = $users[0].PSObject.Properties.Name

$hasFirstName = "FirstName" -in $headers
$hasLastName = "LastName" -in $headers
$hasGivenName = "GivenName" -in $headers
$hasSurname = "Surname" -in $headers
$hasDepartment = "Department" -in $headers

if ($hasFirstName -and $hasLastName) {
    Write-Host "Using FirstName and LastName columns." -ForegroundColor Green
    $usingFirstName = $true
    $usingLastName = $true
    $usingGivenName = $false
    $usingSurname = $false
} elseif ($hasGivenName -and $hasSurname) {
    Write-Host "Using GivenName and Surname columns." -ForegroundColor Green
    $usingFirstName = $false
    $usingLastName = $false
    $usingGivenName = $true
    $usingSurname = $true
} elseif ($hasGivenName -and $hasLastName) {
    Write-Host "Using GivenName and LastName columns." -ForegroundColor Yellow
    $usingFirstName = $false
    $usingLastName = $true
    $usingGivenName = $true
    $usingSurname = $false
} elseif ($hasFirstName -and $hasSurname) {
    Write-Host "Using FirstName and Surname columns." -ForegroundColor Yellow
    $usingFirstName = $true
    $usingLastName = $false
    $usingGivenName = $false
    $usingSurname = $true
} else {
    Write-Error "CSV must contain either (FirstName AND LastName) OR (GivenName AND Surname)"
    Write-Host "Found headers: $($headers -join ', ')" -ForegroundColor Red
    Disconnect-MgGraph
    exit 1
}

if (-not $hasDepartment) {
    Write-Warning "CSV does not have a 'Department' column. Users will not be added to groups."
}

Write-Host "Found CSV headers: $($headers -join ', ')" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Gray

# --- Track departments for group creation ---
$departmentGroups = @{}
$allDepartments = @()

# --- First Pass: Collect all unique departments ---
if ($hasDepartment) {
    Write-Host "📊 Collecting unique departments..." -ForegroundColor Cyan
    foreach ($user in $users) {
        $dept = $user.Department
        if (-not [string]::IsNullOrWhiteSpace($dept)) {
            $dept = $dept.Trim()
            if ($dept -notin $allDepartments) {
                $allDepartments += $dept
            }
        }
    }
    Write-Host "Found $($allDepartments.Count) unique department(s): $($allDepartments -join ', ')" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Gray
}

# --- Create all department groups first (if not CreateGroupsOnly) ---
if ($hasDepartment -and -not $CreateGroupsOnly) {
    Write-Host "📝 Creating department groups..." -ForegroundColor Cyan
    foreach ($dept in $allDepartments) {
        if (-not [string]::IsNullOrWhiteSpace($dept)) {
            $group = Get-CreateDepartmentGroup -DepartmentName $dept -GroupPrefix $GroupPrefix -GroupDescription $GroupDescription
            if ($group) {
                $departmentGroups[$dept] = $group.Id
            }
        }
    }
    Write-Host ("=" * 60) -ForegroundColor Gray
}

# --- If CreateGroupsOnly, exit after creating groups ---
if ($CreateGroupsOnly) {
    Write-Host "✅ Groups created successfully!" -ForegroundColor Green
    Write-Host "`n📋 Created Groups:" -ForegroundColor Cyan
    foreach ($dept in $departmentGroups.Keys) {
        Write-Host "  - $GroupPrefix$dept (ID: $($departmentGroups[$dept]))" -ForegroundColor Gray
    }
    Disconnect-MgGraph
    exit 0
}

# --- Statistics ---
$totalUsers = $users.Count
$createdCount = 0
$skippedCount = 0
$failedCount = 0
$failedUsers = @()
$createdUsers = @()
$skippedUsers = @()
$groupAddSuccess = 0
$groupAddFailed = 0

Write-Host ("=" * 60) -ForegroundColor Gray

# --- Process Each User ---
$counter = 0
foreach ($user in $users) {
    $counter++
    
    # --- Extract name values ---
    if ($usingFirstName -and $usingLastName) {
        $firstName = $user.FirstName
        $lastName = $user.LastName
        $givenName = if ($user.GivenName) { $user.GivenName } else { $firstName }
        $surname = if ($user.Surname) { $user.Surname } else { $lastName }
    } elseif ($usingGivenName -and $usingSurname) {
        $givenName = $user.GivenName
        $surname = $user.Surname
        $firstName = if ($user.FirstName) { $user.FirstName } else { $givenName }
        $lastName = if ($user.LastName) { $user.LastName } else { $surname }
    } elseif ($usingGivenName -and $usingLastName) {
        $givenName = $user.GivenName
        $lastName = $user.LastName
        $firstName = if ($user.FirstName) { $user.FirstName } else { $givenName }
        $surname = if ($user.Surname) { $user.Surname } else { $lastName }
    } elseif ($usingFirstName -and $usingSurname) {
        $firstName = $user.FirstName
        $surname = $user.Surname
        $givenName = if ($user.GivenName) { $user.GivenName } else { $firstName }
        $lastName = if ($user.LastName) { $user.LastName } else { $surname }
    }
    
    # Skip if missing required fields
    if ([string]::IsNullOrWhiteSpace($firstName) -or [string]::IsNullOrWhiteSpace($lastName)) {
        Write-Host "[$counter/$totalUsers] ⚠️ Skipping: Missing FirstName or LastName" -ForegroundColor Yellow
        $failedCount++
        $failedUsers += "Row ${counter}: Missing FirstName or LastName"
        continue
    }
    
    Write-Host "[$counter/$totalUsers] Processing: $firstName $lastName" -ForegroundColor Yellow
    
    # --- Build user properties with defaults ---
    $finalGivenName = if ($givenName) { $givenName } elseif ($GivenName) { $GivenName } else { $firstName }
    $finalSurname = if ($surname) { $surname } elseif ($Surname) { $Surname } else { $lastName }
    
    $displayName = if ($user.DisplayName) { $user.DisplayName } 
                   elseif ($DisplayName) { $DisplayName } 
                   else { "$firstName $lastName" }
    
    $department = if ($user.Department) { $user.Department.Trim() } 
                  elseif ($Department) { $Department } 
                  else { "" }
    
    $jobTitle = if ($user.JobTitle) { $user.JobTitle } elseif ($JobTitle) { $JobTitle } else { "" }
    $accountEnabled = if ($null -ne $user.AccountEnabled) { [bool]$user.AccountEnabled } else { $AccountEnabled }
    $usageLocation = if ($user.UsageLocation) { $user.UsageLocation } else { $UsageLocation }
    $country = if ($user.Country) { $user.Country } elseif ($Country) { $Country } else { "" }
    $officeLocation = if ($user.OfficeLocation) { $user.OfficeLocation } elseif ($OfficeLocation) { $OfficeLocation } else { "" }
    $city = if ($user.City) { $user.City } elseif ($City) { $City } else { "" }
    $mobilePhone = if ($user.MobilePhone) { $user.MobilePhone } elseif ($MobilePhone) { $MobilePhone } else { "" }
    $licenseSku = if ($user.License) { $user.License } elseif ($License) { $License } else { "" }
    
    # --- Generate UserPrincipalName ---
    $userPrincipalName = New-UserPrincipalName -GivenName $finalGivenName -Surname $finalSurname -Domain $Domain
    
    # --- Check if user already exists (using the comprehensive function) ---
    $existingUser = Get-ExistingUser -UserPrincipalName $userPrincipalName
    
    if ($existingUser) {
        if ($SkipExistingUsers) {
            Write-Host "  ⏭️ User already exists, skipping creation: $userPrincipalName" -ForegroundColor Yellow
            $skippedCount++
            
            # Still add existing user to group
            if ($department -and $departmentGroups.ContainsKey($department)) {
                $groupId = $departmentGroups[$department]
                if (Add-UserToGroup -UserId $existingUser.Id -GroupId $groupId) {
                    $groupAddSuccess++
                } else {
                    $groupAddFailed++
                }
            }
            
            $skippedUsers += [PSCustomObject]@{
                UserPrincipalName = $userPrincipalName
                DisplayName = $displayName
                Department = $department
                Status = "Skipped (Already Exists)"
                Group = if ($department -and $departmentGroups.ContainsKey($department)) { "$GroupPrefix$department" } else { "None" }
            }
            
            continue
        } else {
            # --- SkipExistingUsers is FALSE: find a free UPN and create a distinct account ---
            Write-Host "  ℹ️ User already exists but -SkipExistingUsers is FALSE. Creating a new account with a different UPN." -ForegroundColor Cyan
            $counterSuffix = 0
            $originalUPN = $userPrincipalName
            $upnExists = $true
            
            while ($upnExists) {
                $counterSuffix++
                $userPrincipalName = $originalUPN -replace '@', "$counterSuffix@"
                Write-Host "  ℹ️ UPN conflict. Trying: $userPrincipalName" -ForegroundColor Yellow
                $existingUser = Get-ExistingUser -UserPrincipalName $userPrincipalName
                $upnExists = [bool]$existingUser
            }
        }
    }
    
    # --- Generate password ---
    if ($DefaultPassword) {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($DefaultPassword)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    } else {
        $password = New-RandomPassword
    }
    
    # --- Prepare user properties ---
    $userParams = @{
        UserPrincipalName = $userPrincipalName
        DisplayName = $displayName
        GivenName = $finalGivenName
        Surname = $finalSurname
        MailNickname = $userPrincipalName.Split('@')[0]
        AccountEnabled = $accountEnabled
        PasswordProfile = @{
            Password = $password
            ForceChangePasswordNextSignIn = $ForcePasswordChange
        }
        PasswordPolicies = "DisablePasswordExpiration"
        UsageLocation = $usageLocation
    }
    
    # --- Add optional properties ---
    if ($jobTitle) { $userParams.JobTitle = $jobTitle }
    if ($department) { $userParams.Department = $department }
    if ($country) { $userParams.Country = $country }
    if ($officeLocation) { $userParams.OfficeLocation = $officeLocation }
    if ($city) { $userParams.City = $city }
    if ($mobilePhone) { $userParams.MobilePhone = $mobilePhone }
    
    # --- Create the user ---
    if ($DryRun) {
        Write-Host "  🧪 [DRY RUN] Would create: $userPrincipalName" -ForegroundColor Yellow
        Write-Host "    Department: $department" -ForegroundColor Gray
        Write-Host "    Group: $(if ($department -and $departmentGroups.ContainsKey($department)) { "$GroupPrefix$department" } else { 'None' })" -ForegroundColor Gray
        
        $createdCount++
        $createdUsers += [PSCustomObject]@{
            UserPrincipalName = $userPrincipalName
            DisplayName = $displayName
            GivenName = $finalGivenName
            Surname = $finalSurname
            Department = $department
            JobTitle = $jobTitle
            UsageLocation = $usageLocation
            AccountEnabled = $accountEnabled
            License = $licenseSku
            Password = $password
            Status = "Dry Run"
            Group = if ($department -and $departmentGroups.ContainsKey($department)) { "$GroupPrefix$department" } else { "None" }
        }
    } else {
        try {
            Write-Host "  📝 Creating user: $userPrincipalName..." -ForegroundColor Yellow
            $newUser = New-MgUser @userParams -ErrorAction Stop
            
            Write-Host "  ✅ User created successfully!" -ForegroundColor Green
            $createdCount++
            
            # --- Assign License if specified ---
            if ($licenseSku) {
                Assign-LicenseToUser -UserId $newUser.Id -LicenseSku $licenseSku -UsageLocation $usageLocation
            }
            
            # --- Add user to department group ---
            $groupAdded = $false
            if ($department -and $departmentGroups.ContainsKey($department)) {
                $groupId = $departmentGroups[$department]
                if (Add-UserToGroup -UserId $newUser.Id -GroupId $groupId) {
                    $groupAddSuccess++
                    $groupAdded = $true
                } else {
                    $groupAddFailed++
                }
            } else {
                Write-Host "  ℹ️ No department group available for this user." -ForegroundColor Yellow
            }
            
            $createdUsers += [PSCustomObject]@{
                UserPrincipalName = $userPrincipalName
                DisplayName = $displayName
                GivenName = $finalGivenName
                Surname = $finalSurname
                Department = $department
                JobTitle = $jobTitle
                UsageLocation = $usageLocation
                AccountEnabled = $accountEnabled
                License = if ($licenseSku) { "$licenseSku Assigned" } else { "None" }
                Password = $password
                Status = "Created"
                Group = if ($groupAdded) { "$GroupPrefix$department" } else { "None" }
                Id = $newUser.Id
            }
            
        } catch {
            Write-Host "  ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
            $failedCount++
            $failedUsers += "${userPrincipalName}: $($_.Exception.Message)"
        }
    }
    
    Write-Host ("-" * 60) -ForegroundColor Gray
}

# --- Summary ---
Write-Host ("=" * 60) -ForegroundColor Gray
Write-Host "📊 SUMMARY" -ForegroundColor Magenta
Write-Host "  Total Users Processed: $totalUsers" -ForegroundColor White
Write-Host "  ✅ Users Created: $createdCount" -ForegroundColor Green
Write-Host "  ⏭️ Users Skipped (Already Exists): $skippedCount" -ForegroundColor Yellow
Write-Host "  ❌ Users Failed: $failedCount" -ForegroundColor Red
Write-Host ""
Write-Host "📋 Group Summary:" -ForegroundColor Cyan
Write-Host "  📁 Total Department Groups: $($departmentGroups.Count)" -ForegroundColor White
Write-Host "  ✅ Users Added to Groups: $groupAddSuccess" -ForegroundColor Green
Write-Host "  ❌ Users Failed to Add to Groups: $groupAddFailed" -ForegroundColor Red

if ($createdUsers) {
    Write-Host "`n📋 Created Users:" -ForegroundColor Cyan
    $createdUsers | Format-Table UserPrincipalName, DisplayName, Department, Status, Group, Password -AutoSize
}

if ($skippedUsers) {
    Write-Host "`n⏭️ Skipped Users (Already Exists):" -ForegroundColor Yellow
    $skippedUsers | Format-Table UserPrincipalName, DisplayName, Department, Status, Group -AutoSize
}

if ($failedUsers) {
    Write-Host "`n❌ Failed Users:" -ForegroundColor Red
    $failedUsers | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

Write-Host "`n📁 Department Groups Created:" -ForegroundColor Cyan
foreach ($dept in $departmentGroups.Keys) {
    Write-Host "  - $GroupPrefix$dept (ID: $($departmentGroups[$dept]))" -ForegroundColor Gray
}

# --- Export results to CSV ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$resultPath = "UserCreation_Results_$timestamp.csv"
$skippedPath = "SkippedUsers_$timestamp.csv"
$groupResultPath = "DepartmentGroups_$timestamp.csv"

if ($createdUsers) {
    $createdUsers | Export-Csv -Path $resultPath -NoTypeInformation
    Write-Host "`n📁 User results exported to: $resultPath" -ForegroundColor Cyan
}

if ($skippedUsers) {
    $skippedUsers | Export-Csv -Path $skippedPath -NoTypeInformation
    Write-Host "📁 Skipped users exported to: $skippedPath" -ForegroundColor Yellow
}

if ($departmentGroups) {
    $departmentGroups.Keys | ForEach-Object {
        [PSCustomObject]@{
            Department = $_
            GroupName = "$GroupPrefix$_"
            GroupId = $departmentGroups[$_]
        }
    } | Export-Csv -Path $groupResultPath -NoTypeInformation
    Write-Host "📁 Group results exported to: $groupResultPath" -ForegroundColor Cyan
}

# --- Disconnect ---
Disconnect-MgGraph
Write-Host "`nDisconnected from Microsoft Graph." -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "🧪 This was a DRY RUN. No users or groups were actually created." -ForegroundColor Yellow
}