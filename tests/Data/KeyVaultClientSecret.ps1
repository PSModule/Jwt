function Get-KeyVaultClientSecretMissingConfig {
    <#
    .SYNOPSIS
    Returns missing environment variable names required for Key Vault client-secret tests.
    #>
    [CmdletBinding()]
    param()

    $required = @(
        'AZURE_TENANT_ID',
        'AZURE_CLIENT_ID',
        'AZURE_KEYVAULT_NAME',
        'AZURE_KEYVAULT_KEY_NAME',
        'AZURE_CLIENT_SECRET'
    )

    $missing = @()
    foreach ($name in $required) {
        if ([string]::IsNullOrWhiteSpace([System.Environment]::GetEnvironmentVariable($name))) {
            $missing += $name
        }
    }

    return $missing
}

function Get-KeyVaultAccessToken {
    <#
    .SYNOPSIS
    Acquires an Azure AD access token for Key Vault using client credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $TenantId,

        [Parameter(Mandatory)]
        [string] $ClientId,

        [Parameter(Mandatory)]
        [string] $ClientSecret
    )

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = 'https://vault.azure.net/.default'
        grant_type    = 'client_credentials'
    }

    return (Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType 'application/x-www-form-urlencoded').access_token
}

function Invoke-KeyVaultSign {
    <#
    .SYNOPSIS
    Signs a JWT signing-input digest by calling the Azure Key Vault keys/sign endpoint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $VaultName,

        [Parameter(Mandatory)]
        [string] $KeyName,

        [Parameter()]
        [string] $KeyVersion,

        [Parameter(Mandatory)]
        [string] $AccessToken,

        [Parameter(Mandatory)]
        [string] $SigningInput
    )

    $keyPath = if ([string]::IsNullOrWhiteSpace($KeyVersion)) {
        "$KeyName/sign"
    } else {
        "$KeyName/$KeyVersion/sign"
    }
    $uri = 'https://' + $VaultName + '.vault.azure.net/keys/' + $keyPath + '?api-version=7.4'

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($SigningInput)
    $digest = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $digestBase64Url = ConvertTo-Base64UrlString -InputObject $digest

    $headers = @{ Authorization = "Bearer $AccessToken" }
    $body = @{ alg = 'RS256'; value = $digestBase64Url } | ConvertTo-Json -Compress
    return (Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType 'application/json').value
}

function Get-KeyVaultJwkPublicKey {
    <#
    .SYNOPSIS
    Retrieves the public JWK for a Key Vault key and returns it as a JwtKey object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $VaultName,

        [Parameter(Mandatory)]
        [string] $KeyName,

        [Parameter()]
        [string] $KeyVersion,

        [Parameter(Mandatory)]
        [string] $AccessToken
    )

    $keyPath = if ([string]::IsNullOrWhiteSpace($KeyVersion)) {
        $KeyName
    } else {
        "$KeyName/$KeyVersion"
    }
    $uri = 'https://' + $VaultName + '.vault.azure.net/keys/' + $keyPath + '?api-version=7.4'

    $headers = @{ Authorization = "Bearer $AccessToken" }
    $keyResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

    $jwkHash = [ordered]@{
        kty = $keyResponse.key.kty
        n   = $keyResponse.key.n
        e   = $keyResponse.key.e
        kid = $keyResponse.key.kid
    }
    return [JwtKey]::new($jwkHash)
}
