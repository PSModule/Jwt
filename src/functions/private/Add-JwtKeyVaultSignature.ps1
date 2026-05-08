function Add-JwtKeyVaultSignature {
    <#
        .SYNOPSIS
        Signs a JWT using an RSA key stored in Azure Key Vault (RS256).

        .DESCRIPTION
        Computes the SHA-256 digest of the JWT signing input (header.payload), then calls the
        Azure Key Vault Sign REST API (api-version=7.4) to produce an RS256 signature.
        Authentication is obtained from the Azure CLI (`az`) or Az PowerShell (`Get-AzAccessToken`),
        whichever is available. Neither is declared as a module dependency; one must be installed
        and authenticated at call time.

        .EXAMPLE
        ```powershell
        Add-JwtKeyVaultSignature -Jwt $unsigned -KeyVaultKeyReference 'https://myvault.vault.azure.net/keys/mykey'
        ```

        Signs the unsigned JWT using the specified Key Vault key.

        .OUTPUTS
        Jwt
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Required to pass the Key Vault access token to Invoke-RestMethod'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Function mutates the in-memory [Jwt] object only'
    )]
    [CmdletBinding()]
    [OutputType([Jwt])]
    param(
        # The unsigned [Jwt] object to sign.
        [Parameter(Mandatory)]
        [Jwt] $Jwt,

        # The Azure Key Vault key URL used for signing
        # (e.g. https://myvault.vault.azure.net/keys/mykey or .../keys/mykey/<version>).
        [Parameter(Mandatory)]
        [string] $KeyVaultKeyReference
    )

    process {
        $azCli = Get-Command -Name 'az' -CommandType Application -ErrorAction SilentlyContinue
        $azPs = Get-Command -Name 'Get-AzAccessToken' -ErrorAction SilentlyContinue

        if ($azCli) {
            try {
                $accessToken = (& az account get-access-token --resource 'https://vault.azure.net/' --output json |
                    ConvertFrom-Json).accessToken
            } catch {
                throw "Failed to get access token from Azure CLI: $_"
            }
        } elseif ($azPs) {
            try {
                $tokenResult = Get-AzAccessToken -ResourceUrl 'https://vault.azure.net/'
                $accessToken = if ($tokenResult.Token -is [securestring]) {
                    $tokenResult.Token | ConvertFrom-SecureString -AsPlainText
                } else {
                    [string]$tokenResult.Token
                }
            } catch {
                throw "Failed to get access token from Az PowerShell: $_"
            }
        } else {
            throw 'Azure authentication is required. Install and sign in with Azure CLI or Az PowerShell.'
        }

        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Jwt.SigningInput()))
        } finally {
            $sha256.Dispose()
        }
        $hash64url = [JwtBase64Url]::Encode($hashBytes)

        $url = $KeyVaultKeyReference.TrimEnd('/') + '/sign?api-version=7.4'
        $secureToken = ConvertTo-SecureString -String $accessToken -AsPlainText -Force

        $params = @{
            Method         = 'POST'
            Uri            = $url
            Body           = (@{ alg = 'RS256'; value = $hash64url } | ConvertTo-Json -Compress)
            ContentType    = 'application/json'
            Authentication = 'Bearer'
            Token          = $secureToken
        }

        $result = Invoke-RestMethod @params
        $Jwt.Signature = [string]$result.value
        return $Jwt
    }
}
