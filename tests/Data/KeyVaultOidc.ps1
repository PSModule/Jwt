function Get-KeyVaultOidcMissingConfig {
    [CmdletBinding()]
    param()

    $required = @(
        'AZURE_TENANT_ID',
        'AZURE_CLIENT_ID',
        'AZURE_SUBSCRIPTION_ID',
        'AZURE_KEYVAULT_NAME',
        'AZURE_KEYVAULT_KEY_NAME'
    )

    $missing = @()
    foreach ($name in $required) {
        if ([string]::IsNullOrWhiteSpace([System.Environment]::GetEnvironmentVariable($name))) {
            $missing += $name
        }
    }

    return $missing
}

function Get-GitHubOidcToken {
    [CmdletBinding()]
    param()

    if ([string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN) -or
        [string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_URL)) {
        throw 'GitHub OIDC request environment variables are unavailable.'
    }

    $uri = "$($env:ACTIONS_ID_TOKEN_REQUEST_URL)&audience=api://AzureADTokenExchange"
    $headers = @{ Authorization = "Bearer $($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN)" }
    return (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value
}

function Get-KeyVaultAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $TenantId,

        [Parameter(Mandatory)]
        [string] $ClientId,

        [Parameter(Mandatory)]
        [string] $GitHubOidcToken
    )

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id             = $ClientId
        scope                 = 'https://vault.azure.net/.default'
        grant_type            = 'client_credentials'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $GitHubOidcToken
    }

    return (Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType 'application/x-www-form-urlencoded').access_token
}

function Invoke-KeyVaultSign {
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
    $digestBase64Url = ConvertTo-Base64UrlString -InputObject $digest -NoEnumerateByteArray

    $headers = @{ Authorization = "Bearer $AccessToken" }
    $body = @{ alg = 'RS256'; value = $digestBase64Url } | ConvertTo-Json -Compress
    return (Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType 'application/json').value
}

function Get-KeyVaultJwkPublicKey {
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
