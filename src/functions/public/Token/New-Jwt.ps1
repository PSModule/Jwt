function New-Jwt {
    <#
        .SYNOPSIS
        Creates a JSON Web Token.

        .DESCRIPTION
        Builds a [Jwt] from a header overrides hashtable and a claims payload.
        The default signed mode takes -Key. The generated-key mode (-GenerateKey)
        creates a compatible signing key internally using New-JwtSigningKey.
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
        $result = New-Jwt -Payload @{ sub = 'app' } -Algorithm ES256 -GenerateKey -IncludeGeneratedKey
        $result.Token
        $result.Key

        Generates a key internally, signs the token, and returns both token and key.
        .LINK
        https://psmodule.io/Jwt/Functions/Token/New-Jwt/

        .OUTPUTS
        System.Object
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'New-Jwt builds an in-memory token and does not change system state.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseOutputTypeCorrectly', '',
        Justification = 'Returns Jwt normally, or a PSCustomObject bundle when -IncludeGeneratedKey is used.'
    )]
    [OutputType([object])]
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

        # Include the generated key in the return object.
        [Parameter(ParameterSetName = 'GeneratedSigned')]
        [switch] $IncludeGeneratedKey,

        # Include a generated JWK (with private parameters) in the return object.
        [Parameter(ParameterSetName = 'GeneratedSigned')]
        [switch] $IncludeGeneratedJwk,

        # RSA key size when generating RS*/PS* keys.
        [Parameter(ParameterSetName = 'GeneratedSigned')]
        [ValidateSet(2048, 3072, 4096)]
        [int] $RsaKeySize = 2048,

        # Optional key id used for generated JWK output and as default header.kid.
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
        if ($IncludeGeneratedJwk -and -not $IncludeGeneratedKey) {
            throw [System.ArgumentException]::new(
                '-IncludeGeneratedJwk requires -IncludeGeneratedKey.',
                'IncludeGeneratedJwk'
            )
        }

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
        if ($PSCmdlet.ParameterSetName -eq 'GeneratedSigned') {
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
            $isGeneratedAsymmetric = (
                $PSCmdlet.ParameterSetName -eq 'GeneratedSigned' -and
                $generatedKey -is [System.IDisposable]
            )
            $shouldDispose = $false
            if ($resolved -is [System.IDisposable]) {
                if ($isGeneratedAsymmetric) {
                    $shouldDispose = -not $IncludeGeneratedKey
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

        if ($PSCmdlet.ParameterSetName -eq 'GeneratedSigned' -and $IncludeGeneratedKey) {
            $result = [ordered]@{
                Token = $token
                Key = $generatedKey
            }
            if ($IncludeGeneratedJwk) {
                $result['Jwk'] = ConvertTo-JwtKey -Key $generatedKey -IncludePrivateParameters -Algorithm $Algorithm -KeyId $GeneratedKeyId
            }
            return [pscustomobject]$result
        }

        return $token
    }
}
