function ConvertTo-JwtKey {
    <#
        .SYNOPSIS
        Convert a .NET key to a JWK ([JwtKey]).

        .DESCRIPTION
        Converts an `RSA`, `ECDsa`, or `byte[]` (HMAC secret) instance into a
        `[JwtKey]` representation per RFC 7517 / RFC 7518.
        Private fields are included only when `-IncludePrivate` is passed.

        Supported key types and their JWK `kty`:
          RSA                              → kty=RSA
          ECDsa (P-256, P-384, P-521)      → kty=EC
          byte[]                           → kty=oct

        .EXAMPLE
        ```powershell
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $jwk = ConvertTo-JwtKey -Key $rsa -Use 'sig' -Alg 'RS256' -Kid 'key-1'
        ```

        Returns a `[JwtKey]` with `kty='RSA'`.

        .OUTPUTS
        JwtKey
    #>
    [OutputType([JwtKey])]
    [CmdletBinding()]
    param(
        # The .NET key to convert.
        [Parameter(Mandatory, Position = 0)]
        [object] $Key,

        # Optional `use` field (e.g., `sig`, `enc`).
        [Parameter()]
        [string] $Use,

        # Optional `alg` field.
        [Parameter()]
        [string] $Alg,

        # Optional `kid` field.
        [Parameter()]
        [string] $Kid,

        # Include private key material in the JWK.
        [Parameter()]
        [switch] $IncludePrivate
    )

    $jwk = [JwtKey]::new()
    if ($PSBoundParameters.ContainsKey('Use')) { $jwk.use = $Use }
    if ($PSBoundParameters.ContainsKey('Alg')) { $jwk.alg = $Alg }
    if ($PSBoundParameters.ContainsKey('Kid')) { $jwk.kid = $Kid }

    if ($Key -is [System.Security.Cryptography.RSA]) {
        $params = $Key.ExportParameters($IncludePrivate.IsPresent)
        $jwk.kty = 'RSA'
        $jwk.n = [JwtBase64Url]::Encode($params.Modulus)
        $jwk.e = [JwtBase64Url]::Encode($params.Exponent)
        if ($IncludePrivate -and $null -ne $params.D) {
            $jwk.d = [JwtBase64Url]::Encode($params.D)
            $jwk.p = [JwtBase64Url]::Encode($params.P)
            $jwk.q = [JwtBase64Url]::Encode($params.Q)
            $jwk.dp = [JwtBase64Url]::Encode($params.DP)
            $jwk.dq = [JwtBase64Url]::Encode($params.DQ)
            $jwk.qi = [JwtBase64Url]::Encode($params.InverseQ)
        }
        return $jwk
    }

    if ($Key -is [System.Security.Cryptography.ECDsa]) {
        $params = $Key.ExportParameters($IncludePrivate.IsPresent)
        $jwk.kty = 'EC'
        $curveName = $params.Curve.Oid.FriendlyName
        $jwk.crv = switch -Regex ($curveName) {
            'nistP256|ECDSA_P256|secP256r1|prime256v1' { 'P-256'; break }
            'nistP384|ECDSA_P384|secP384r1' { 'P-384'; break }
            'nistP521|ECDSA_P521|secP521r1' { 'P-521'; break }
            default { $curveName }
        }
        $jwk.x = [JwtBase64Url]::Encode($params.Q.X)
        $jwk.y = [JwtBase64Url]::Encode($params.Q.Y)
        if ($IncludePrivate -and $null -ne $params.D) {
            $jwk.d = [JwtBase64Url]::Encode($params.D)
        }
        return $jwk
    }

    if ($Key -is [byte[]]) {
        $jwk.kty = 'oct'
        $jwk.k = [JwtBase64Url]::Encode([byte[]]$Key)
        return $jwk
    }

    throw "Unsupported key type [$($Key.GetType().FullName)]. Supported: RSA, ECDsa, byte[]."
}
