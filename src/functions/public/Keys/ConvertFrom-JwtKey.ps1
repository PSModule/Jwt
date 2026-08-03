function ConvertFrom-JwtKey {
    <#
        .SYNOPSIS
        Converts a [JwtKey] (JWK) into a .NET key suitable for signing or verification.

        .DESCRIPTION
        Returns an [RSA], [ECDsa], or [byte[]] depending on the JWK kty:

        - kty='RSA' → [RSA] populated from n/e (and optionally d/p/q/dp/dq/qi).
        - kty='EC'  → [ECDsa] populated from crv/x/y (and optionally d).
        - kty='oct' → raw secret [byte[]] decoded from k.

        Use -AsHmac to materialize an [HMAC] instance for oct keys when needed.

        .EXAMPLE
        $rsa = ConvertFrom-JwtKey -Key $jwk

        Returns an RSA usable with Test-Jwt -Key $rsa.

        .EXAMPLE
        $hmac = ConvertFrom-JwtKey -Key $octJwk -AsHmac -Algorithm HS512

        Returns an HMACSHA512 from an oct JWK.
        .LINK
        https://psmodule.io/Jwt/Functions/Keys/ConvertFrom-JwtKey/

        .INPUTS
        JwtKey

        .OUTPUTS
        System.Security.Cryptography.RSA
        System.Security.Cryptography.ECDsa
        System.Byte[]
        System.Security.Cryptography.HMAC

        .NOTES
        Returning raw bytes for oct avoids implicit algorithm coupling in the conversion layer.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseOutputTypeCorrectly', '',
        Justification = 'Returns RSA/ECDsa/byte[] by default and HMAC for oct with -AsHmac.'
    )]
    [OutputType([System.Security.Cryptography.AsymmetricAlgorithm], [byte[]], [System.Security.Cryptography.HMAC])]
    [CmdletBinding()]
    param(
        # The JWK to convert.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [JwtKey] $Key,

        # Return an HMAC instance for oct keys instead of raw secret bytes.
        [Parameter()]
        [switch] $AsHmac,

        # HMAC algorithm used with -AsHmac.
        [Parameter()]
        [ValidateSet('HS256', 'HS384', 'HS512')]
        [string] $Algorithm = 'HS256'
    )

    process {
        if ($AsHmac -and $Key.kty -ne 'oct') {
            throw [System.ArgumentException]::new(
                '-AsHmac is only supported for JWK keys where kty=oct.',
                'AsHmac'
            )
        }

        switch ($Key.kty) {
            'RSA' {
                $params = [System.Security.Cryptography.RSAParameters]::new()
                $params.Modulus = [JwtBase64Url]::Decode($Key.n)
                $params.Exponent = [JwtBase64Url]::Decode($Key.e)
                if ($Key.d) {
                    $params.D = [JwtBase64Url]::Decode($Key.d)
                    $params.P = [JwtBase64Url]::Decode($Key.p)
                    $params.Q = [JwtBase64Url]::Decode($Key.q)
                    $params.DP = [JwtBase64Url]::Decode($Key.dp)
                    $params.DQ = [JwtBase64Url]::Decode($Key.dq)
                    $params.InverseQ = [JwtBase64Url]::Decode($Key.qi)
                }
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $rsa.ImportParameters($params)
                return $rsa
            }
            'EC' {
                $curve = switch ($Key.crv) {
                    'P-256' { [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7') }
                    'P-384' { [System.Security.Cryptography.ECCurve]::CreateFromValue('1.3.132.0.34') }
                    'P-521' { [System.Security.Cryptography.ECCurve]::CreateFromValue('1.3.132.0.35') }
                    default { throw [System.NotSupportedException]::new("EC curve '$($Key.crv)' is not supported.") }
                }
                $point = [System.Security.Cryptography.ECPoint]@{
                    X = [JwtBase64Url]::Decode($Key.x)
                    Y = [JwtBase64Url]::Decode($Key.y)
                }
                $params = [System.Security.Cryptography.ECParameters]@{
                    Curve = $curve
                    Q     = $point
                }
                if ($Key.d) {
                    $params.D = [JwtBase64Url]::Decode($Key.d)
                }
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                $ecdsa.ImportParameters($params)
                return $ecdsa
            }
            'oct' {
                $bytes = [JwtBase64Url]::Decode($Key.k)
                if ($AsHmac) {
                    return New-JwtHmac -Algorithm $Algorithm -KeyBytes $bytes
                }
                return $bytes
            }
            default {
                throw [System.NotSupportedException]::new("JWK kty '$($Key.kty)' is not supported.")
            }
        }
    }
}

