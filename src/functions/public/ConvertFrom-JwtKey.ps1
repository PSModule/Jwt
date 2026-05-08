function ConvertFrom-JwtKey {
    <#
        .SYNOPSIS
        Convert a JWK ([JwtKey]) into a .NET key.

        .DESCRIPTION
        Materializes a `[JwtKey]` (RFC 7517 / RFC 8037) into a usable .NET cryptographic
        instance. Private parameters are imported when the JWK contains them.

        Supported JWK `kty` values:
          RSA  → [System.Security.Cryptography.RSA]
          EC   → [System.Security.Cryptography.ECDsa] (P-256, P-384, P-521)
          oct  → [byte[]]

        .EXAMPLE
        $rsa = ConvertFrom-JwtKey -JwtKey $jwk

        Returns an `RSA` instance suitable for verification.

        .OUTPUTS
        System.Security.Cryptography.RSA, System.Security.Cryptography.ECDsa,
        System.Security.Cryptography.Ed25519, or System.Byte[]
    #>
    [OutputType([System.Security.Cryptography.RSA], [System.Security.Cryptography.ECDsa], [byte[]])]
    [CmdletBinding()]
    param(
        # The JWK to convert.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [JwtKey] $JwtKey
    )

    process {
        switch ($JwtKey.kty) {
            'RSA' {
                $rsaParams = [System.Security.Cryptography.RSAParameters]::new()
                $rsaParams.Modulus = [JwtBase64Url]::Decode($JwtKey.n)
                $rsaParams.Exponent = [JwtBase64Url]::Decode($JwtKey.e)
                if (-not [string]::IsNullOrEmpty($JwtKey.d)) {
                    $rsaParams.D = [JwtBase64Url]::Decode($JwtKey.d)
                    $rsaParams.P = [JwtBase64Url]::Decode($JwtKey.p)
                    $rsaParams.Q = [JwtBase64Url]::Decode($JwtKey.q)
                    $rsaParams.DP = [JwtBase64Url]::Decode($JwtKey.dp)
                    $rsaParams.DQ = [JwtBase64Url]::Decode($JwtKey.dq)
                    $rsaParams.InverseQ = [JwtBase64Url]::Decode($JwtKey.qi)
                }
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $rsa.ImportParameters($rsaParams)
                return $rsa
            }
            'EC' {
                $curve = switch ($JwtKey.crv) {
                    'P-256' { [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256') }
                    'P-384' { [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP384') }
                    'P-521' { [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP521') }
                    default { throw "Unsupported EC curve '$($JwtKey.crv)'." }
                }
                $ecParams = [System.Security.Cryptography.ECParameters]::new()
                $ecParams.Curve = $curve
                $point = [System.Security.Cryptography.ECPoint]::new()
                $point.X = [JwtBase64Url]::Decode($JwtKey.x)
                $point.Y = [JwtBase64Url]::Decode($JwtKey.y)
                $ecParams.Q = $point
                if (-not [string]::IsNullOrEmpty($JwtKey.d)) {
                    $ecParams.D = [JwtBase64Url]::Decode($JwtKey.d)
                }
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                $ecdsa.ImportParameters($ecParams)
                return $ecdsa
            }
            'oct' {
                return , [JwtBase64Url]::Decode($JwtKey.k)
            }
            default {
                throw "Unsupported JWK kty '$($JwtKey.kty)'. Supported: RSA, EC, oct."
            }
        }
    }
}
