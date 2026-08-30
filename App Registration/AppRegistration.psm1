# Complete PowerShell Script for Application Registration in Microsoft Entra ID
# This script automates the process of creating an app registration, generating a secret,
# and preparing it for use.

# --- Step 1: Install the Microsoft Graph PowerShell SDK (Run only if not installed) ---
# Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber

# --- Step 2: Connect to Microsoft Graph ---
# You need the "Application.ReadWrite.All" scope to create and manage app registrations.
# Using delegated permissions, an administrator will need to sign in.
Write-Host "Connecting to Microsoft Graph. Please sign in as an administrator..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All" -ErrorAction Stop
Write-Host "Successfully connected." -ForegroundColor Green

# --- Step 3: Define Application Parameters ---
# Define the name and other settings for your new application.
$appDisplayName = "MyAutomationApp" # Change this to your desired app name
$signInAudience = "AzureADMyOrg" # For single-tenant applications
$redirectUri = "http://localhost" # A common redirect URI for native apps/scripts

Write-Host "Preparing to create application: $appDisplayName" -ForegroundColor Yellow

# --- Step 4: Create the Application Registration ---
# This is the core command to create the app registration. The '-Web' parameter handles redirect URIs.
try {
    $appRegistration = New-MgApplication -DisplayName $appDisplayName -SignInAudience $signInAudience `
        -Web @{RedirectUris = @($redirectUri)} -ErrorAction Stop

    Write-Host "Application created successfully." -ForegroundColor Green
    Write-Host "Application (Client) ID: $($appRegistration.AppId)" -ForegroundColor Yellow
    Write-Host "Object ID: $($appRegistration.Id)" -ForegroundColor Yellow
} catch {
    Write-Error "Failed to create application: $_"
    # Disconnect from Graph if an error occurs
    Disconnect-MgGraph
    return
}

# --- Step 5: Create a Client Secret ---
# For applications using app-only authentication, you need a client secret or a certificate.
try {
    $passwordCredential = @{
        DisplayName = "DefaultSecret"
        EndDateTime = (Get-Date).AddYears(1) # Secret valid for 1 year
    }

    Write-Host "Generating a new client secret..." -ForegroundColor Cyan
    $secret = Add-MgApplicationPassword -ApplicationId $appRegistration.Id -PasswordCredential $passwordCredential -ErrorAction Stop

    Write-Host "Client secret generated successfully." -ForegroundColor Green
    # IMPORTANT: The secret text is only visible at this moment!
    Write-Host "Client Secret: $($secret.SecretText)" -ForegroundColor Red
} catch {
    Write-Error "Failed to create client secret: $_"
    Disconnect-MgGraph
    return
}

# --- Step 6: Summary of Information for Your Script ---
Write-Host "`n--- APPLICATION REGISTRATION SUMMARY ---" -ForegroundColor Cyan
Write-Host "Application Name: $appDisplayName"
Write-Host "Application (Client) ID: $($appRegistration.AppId)"
Write-Host "Tenant ID: $((Get-MgContext).TenantId)"
Write-Host "Client Secret (Save this now!): $($secret.SecretText)"
Write-Host "Redirect URI: $redirectUri"

Write-Host "`n-- Next Steps --" -ForegroundColor Yellow
Write-Host "1. Go to the Azure portal (Entra admin center)."
Write-Host "2. Navigate to your new app registration."
Write-Host "3. Under 'API permissions', add permissions (e.g., User.Read.All) and grant admin consent."
Write-Host "4. You can now use this App ID and Secret to authenticate in scripts using app-only access."

# --- Step 7: Disconnect from Graph ---
Disconnect-MgGraph
Write-Host "`nDisconnected from Microsoft Graph." -ForegroundColor Cyan