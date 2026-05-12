function New-Jwt {
    <#
        .SYNOPSIS
        Creates a JSON Web Token.

        .DESCRIPTION
        Builds a [Jwt] from a header overrides hashtable and a claims payload.
        The default mode signs the token with the supplied -Key using the requested
        -Algorithm. The -Unsigned switch produces a token with an empty signature so
        the signature can be attached by an external signing process (HSM, Azure
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

        .OUTPUTS
        Jwt
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'New-Jwt builds an in-memory token and does not change system state.'
    )]
    [OutputType([Jwt])]
    [CmdletBinding(DefaultParameterSetName = 'Signed')]
    param(
        # Optional header overrides. alg and typ are set automatically.
        [Parameter()]
        [hashtable] $Header,

        # The JWT claims hashtable. Registered claims are recognized; the rest flow as private claims.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [hashtable] $Payload,

        # The signing key. Format depends on -Algorithm.
        [Parameter(Mandatory, ParameterSetName = 'Signed')]
        [object] $Key,

        # Produce an unsigned token. The signature must be attached externally via $jwt.Signature.
        [Parameter(Mandatory, ParameterSetName = 'Unsigned')]
        [switch] $Unsigned,

        # The signing algorithm.
        [Parameter()]
        [ValidateSet('RS256', 'HS256', 'ES256')]
        [string] $Algorithm = 'RS256'
    )

    process {
        $headerValues = @{}
        if ($Header) { foreach ($k in $Header.Keys) { $headerValues[$k] = $Header[$k] } }
        $headerValues['alg'] = $Algorithm
        if (-not $headerValues.ContainsKey('typ')) { $headerValues['typ'] = 'JWT' }

        $jwtHeader = [JwtHeader]::new($headerValues)
        $jwtPayload = [JwtPayload]::new($Payload)
        $token = [Jwt]::new($jwtHeader, $jwtPayload)

        if ($Unsigned) {
            $token.Signature = ''
            return $token
        }

        $resolved = Resolve-JwtKey -Algorithm $Algorithm -Key $Key
        $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($token.SigningInput())
        try {
            switch ($Algorithm) {
                'RS256' {
                    $rsa = [System.Security.Cryptography.RSA] $resolved
                    $sigBytes = $rsa.SignData(
                        $contentBytes,
                        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                    )
                }
                'HS256' {
                    $hmac = [System.Security.Cryptography.HMAC] $resolved
                    $sigBytes = $hmac.ComputeHash($contentBytes)
                }
                'ES256' {
                    $ecdsa = [System.Security.Cryptography.ECDsa] $resolved
                    $sigBytes = $ecdsa.SignData(
                        $contentBytes,
                        [System.Security.Cryptography.HashAlgorithmName]::SHA256
                    )
                }
            }
            $token.Signature = [JwtBase64Url]::Encode($sigBytes)
        } finally {
            if ($resolved -is [System.IDisposable] -and $resolved -isnot [System.Security.Cryptography.RSA] -and $Key -isnot [System.Security.Cryptography.RSA] -and $Key -isnot [System.Security.Cryptography.ECDsa]) {
                $resolved.Dispose()
            }
        }
        return $token
    }
}
