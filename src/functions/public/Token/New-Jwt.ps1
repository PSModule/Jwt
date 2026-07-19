function New-Jwt {
    <#
        .SYNOPSIS
        Creates a JSON Web Token.

        .DESCRIPTION
        Builds a [Jwt] from a header overrides hashtable and a claims payload.
        The default signed mode takes -Key. The generated-key mode (-GenerateKey)
        creates a compatible signing key internally using New-JwtSigningKey and
        keeps New-Jwt output shape stable as [Jwt].
        The -Unsigned switch produces a token with an empty signature so the
        signature can be attached by an external signing process (HSM, Azure
        Key Vault, etc.) by writing to $jwt.Signature.

        Header alg and typ are set automatically. Pass kid or other JOSE fields via
        -Header. Registered claims (iss, sub, aud, exp, nbf, iat, jti) on -Payload are
        recognized; other entries flow through as private claims.

        All JSON serialization uses -Depth 100 -Compress to preserve nested claim values.

        .EXAMPLE
        $jwt = New-Jwt -Payload @{ sub = 'user@example.com'; exp = 1900000000 } -Key $secret -Algorithm HS256

        Creates an HS256-signed JWT.

        .EXAMPLE
        $jwt = New-Jwt -Payload @{ sub = 'app' } -Algorithm RS256 -Unsigned
        $jwt.SigningInput() | Send-ToKeyVault | ForEach-Object { $jwt.Signature = $_ }

        Creates an unsigned token, signs the SigningInput externally, and attaches the result.

        .EXAMPLE
        $jwt = New-Jwt -Payload @{ sub = 'app' } -Algorithm ES256 -GenerateKey

        Generates a key internally and returns a signed [Jwt].
        .LINK
        https://psmodule.io/Jwt/Functions/Token/New-Jwt/

        .INPUTS
        System.Collections.IDictionary

        .OUTPUTS
        Jwt

        .NOTES
        Use New-JwtSigningKey if the caller needs to retain or export generated key material.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'New-Jwt builds an in-memory token and does not change system state.'
    )]
    [OutputType([Jwt])]
    [CmdletBinding(DefaultParameterSetName = 'SignedWithKey')]
    param(
        # Optional header overrides. alg and typ are set automatically.
        [Parameter()]
        [System.Collections.IDictionary] $Header,

        # The JWT claims dictionary. Pass an [ordered]@{} to control on-the-wire JSON key order.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [System.Collections.IDictionary] $Payload,

        # The signing key. Format depends on -Algorithm.
        [Parameter(Mandatory, ParameterSetName = 'SignedWithKey')]
        [object] $Key,

        # Generate a compatible key internally and sign with it.
        [Parameter(Mandatory, ParameterSetName = 'GeneratedSigned')]
        [switch] $GenerateKey,

        # RSA key size when generating RS*/PS* keys.
        [Parameter(ParameterSetName = 'GeneratedSigned')]
        [ValidateSet(2048, 3072, 4096)]
        [int] $RsaKeySize = 2048,

        # Optional key id used as default header.kid in generated-key mode.
        [Parameter(ParameterSetName = 'GeneratedSigned')]
        [string] $GeneratedKeyId,

        # Produce an unsigned token. The signature must be attached externally via $jwt.Signature.
        [Parameter(Mandatory, ParameterSetName = 'Unsigned')]
        [switch] $Unsigned,

        # The signing algorithm.
        [Parameter()]
        [ValidateSet(
            'HS256', 'HS384', 'HS512',
            'RS256', 'RS384', 'RS512',
            'ES256', 'ES384', 'ES512',
            'PS256', 'PS384', 'PS512'
        )]
        [string] $Algorithm = 'RS256'
    )

    process {
        $headerValues = [ordered]@{}
        if ($Header) { foreach ($k in $Header.Keys) { $headerValues[$k] = $Header[$k] } }
        $headerValues['alg'] = $Algorithm
        if (-not $headerValues.Contains('typ')) { $headerValues['typ'] = 'JWT' }
        if ($PSCmdlet.ParameterSetName -eq 'GeneratedSigned' -and $GeneratedKeyId -and -not $headerValues.Contains('kid')) {
            $headerValues['kid'] = $GeneratedKeyId
        }

        $jwtHeader = [JwtHeader]::new($headerValues)
        $jwtPayload = [JwtPayload]::new($Payload)
        $token = [Jwt]::new($jwtHeader, $jwtPayload)

        if ($Unsigned) {
            $token.Signature = ''
            return $token
        }

        $effectiveKey = $Key
        $generatedKey = $null
        if ($GenerateKey.IsPresent) {
            $generatedKey = New-JwtSigningKey -Algorithm $Algorithm -RsaKeySize $RsaKeySize
            $effectiveKey = $generatedKey
        }

        $resolved = Resolve-JwtKey -Algorithm $Algorithm -Key $effectiveKey
        $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($token.SigningInput())
        $hash = Get-JwtAlgorithmHash -Algorithm $Algorithm
        try {
            switch -Regex ($Algorithm) {
                '^RS' {
                    $rsa = [System.Security.Cryptography.RSA] $resolved
                    $sigBytes = $rsa.SignData(
                        $contentBytes,
                        $hash,
                        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                    )
                }
                '^PS' {
                    $rsa = [System.Security.Cryptography.RSA] $resolved
                    $sigBytes = $rsa.SignData(
                        $contentBytes,
                        $hash,
                        [System.Security.Cryptography.RSASignaturePadding]::Pss
                    )
                }
                '^HS' {
                    $hmac = [System.Security.Cryptography.HMAC] $resolved
                    $sigBytes = $hmac.ComputeHash($contentBytes)
                }
                '^ES' {
                    $ecdsa = [System.Security.Cryptography.ECDsa] $resolved
                    $sigBytes = $ecdsa.SignData($contentBytes, $hash)
                }
            }
            $token.Signature = [JwtBase64Url]::Encode($sigBytes)
        } finally {
            $shouldDispose = $false
            if ($resolved -is [System.IDisposable]) {
                if ($generatedKey -is [System.IDisposable]) {
                    $shouldDispose = $true
                } else {
                    $shouldDispose = (
                        $effectiveKey -isnot [System.Security.Cryptography.RSA] -and
                        $effectiveKey -isnot [System.Security.Cryptography.ECDsa]
                    )
                }
            }
            if ($shouldDispose) {
                $resolved.Dispose()
            }
        }

        return $token
    }
}
