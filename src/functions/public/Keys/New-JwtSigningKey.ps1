function New-JwtSigningKey {
    <#
        .SYNOPSIS
        Generates a signing key compatible with a JWS algorithm.

        .DESCRIPTION
        Creates a new key for HS*, RS*/PS*, or ES* algorithms using .NET cryptography
        primitives. Returns a .NET key by default:

        - HS*  -> byte[]
        - RS*/PS* -> RSA
        - ES* -> ECDsa

        Use -AsJwk to return a [JwtKey] instead (with private parameters included)
        so the generated key can be serialized or transported.

        .EXAMPLE
        $key = New-JwtSigningKey -Algorithm ES256
        $jwt = New-Jwt -Payload @{ sub = 'app' } -Algorithm ES256 -Key $key

        Generates an EC P-256 key and uses it directly for signing.

        .EXAMPLE
        $jwk = New-JwtSigningKey -Algorithm RS256 -AsJwk -KeyId 'rsa-1'

        Generates a private RSA key and returns it as a [JwtKey].
        .LINK
        https://psmodule.io/Jwt/Functions/Keys/New-JwtSigningKey/

        .INPUTS
        None

        .OUTPUTS
        System.Byte[]
        System.Security.Cryptography.RSA
        System.Security.Cryptography.ECDsa
        JwtKey

        .NOTES
        Use -AsJwk when generated private material must be serialized and stored.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseOutputTypeCorrectly', '',
        Justification = 'Returns byte[]/RSA/ECDsa by algorithm family, or JwtKey with -AsJwk.'
    )]
    [OutputType([byte[]], [System.Security.Cryptography.RSA], [System.Security.Cryptography.ECDsa], [JwtKey])]
    [CmdletBinding(DefaultParameterSetName = 'DotNetKey')]
    param(
        # The algorithm family to generate a key for.
        [Parameter(Mandatory)]
        [ValidateSet(
            'HS256', 'HS384', 'HS512',
            'RS256', 'RS384', 'RS512',
            'ES256', 'ES384', 'ES512',
            'PS256', 'PS384', 'PS512'
        )]
        [string] $Algorithm,

        # RSA modulus size for RS*/PS* generation.
        [Parameter()]
        [ValidateSet(2048, 3072, 4096)]
        [int] $RsaKeySize = 2048,

        # Return a JwtKey (JWK) instead of a .NET key.
        [Parameter(Mandatory, ParameterSetName = 'Jwk')]
        [switch] $AsJwk,

        # Optional key id to stamp on returned JWK.
        [Parameter(ParameterSetName = 'Jwk')]
        [string] $KeyId
    )

    process {
        $key = $null
        switch -Regex ($Algorithm) {
            '^HS' {
                $keyLength = switch ($Algorithm) {
                    'HS256' { 32 }
                    'HS384' { 48 }
                    'HS512' { 64 }
                    default { throw [System.NotSupportedException]::new("Algorithm '$Algorithm' is not supported.") }
                }
                $bytes = [byte[]]::new($keyLength)
                [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
                $key = $bytes
            }
            '^(RS|PS)' {
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $rsa.KeySize = $RsaKeySize
                $key = $rsa
            }
            '^ES' {
                $curveOid = switch ($Algorithm) {
                    'ES256' { '1.2.840.10045.3.1.7' }
                    'ES384' { '1.3.132.0.34' }
                    'ES512' { '1.3.132.0.35' }
                    default { throw [System.NotSupportedException]::new("Algorithm '$Algorithm' is not supported.") }
                }
                $key = [System.Security.Cryptography.ECDsa]::Create(
                    [System.Security.Cryptography.ECCurve]::CreateFromValue($curveOid)
                )
            }
            default {
                throw [System.NotSupportedException]::new("Algorithm '$Algorithm' is not supported.")
            }
        }

        if ($AsJwk) {
            try {
                return ConvertTo-JwtKey -Key $key -IncludePrivateParameters -Algorithm $Algorithm -KeyId $KeyId
            } finally {
                if ($key -is [System.IDisposable]) {
                    $key.Dispose()
                }
            }
        }

        return $key
    }
}
