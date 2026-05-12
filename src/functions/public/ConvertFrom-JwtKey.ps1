function ConvertFrom-JwtKey {
    <#
        .SYNOPSIS
        Converts a [JwtKey] (JWK) into a .NET key suitable for signing or verification.

        .DESCRIPTION
        Returns an [RSA], [ECDsa], or [HMAC] depending on the JWK kty:

        - kty='RSA' → [RSA] populated from n/e (and optionally d/p/q/dp/dq/qi).
        - kty='EC'  → [ECDsa] populated from crv/x/y (and optionally d).
        - kty='oct' → [HMACSHA256] populated from k. The hash size matches the JWK alg
                      (HS256 default).

        .EXAMPLE
        $rsa = ConvertFrom-JwtKey -Key $jwk

        Returns an RSA usable with Test-Jwt -Key $rsa.

        .OUTPUTS
        System.Security.Cryptography.RSA
        System.Security.Cryptography.ECDsa
        System.Security.Cryptography.HMAC
    #>
    [OutputType([System.Security.Cryptography.AsymmetricAlgorithm], [System.Security.Cryptography.HMAC])]
    [CmdletBinding()]
    param(
        # The JWK to convert.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [JwtKey] $Key
    )

    process {
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
                    'P-256' { [System.Security.Cryptography.ECCurve]::NamedCurves.nistP256 }
                    'P-384' { [System.Security.Cryptography.ECCurve]::NamedCurves.nistP384 }
                    'P-521' { [System.Security.Cryptography.ECCurve]::NamedCurves.nistP521 }
                    default { throw [System.NotSupportedException]::new("EC curve '$($Key.crv)' is not supported.") }
                }
                $params = [System.Security.Cryptography.ECParameters]::new()
                $params.Curve = $curve
                $params.Q = [System.Security.Cryptography.ECPoint]::new()
                $params.Q.X = [JwtBase64Url]::Decode($Key.x)
                $params.Q.Y = [JwtBase64Url]::Decode($Key.y)
                if ($Key.d) {
                    $params.D = [JwtBase64Url]::Decode($Key.d)
                }
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                $ecdsa.ImportParameters($params)
                return $ecdsa
            }
            'oct' {
                $bytes = [JwtBase64Url]::Decode($Key.k)
                return [System.Security.Cryptography.HMACSHA256]::new($bytes)
            }
            default {
                throw [System.NotSupportedException]::new("JWK kty '$($Key.kty)' is not supported.")
            }
        }
        return $null
    }
}
