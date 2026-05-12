function ConvertTo-JwtKey {
    <#
        .SYNOPSIS
        Converts a .NET key into a [JwtKey] (JWK).

        .DESCRIPTION
        Accepts an [RSA], [ECDsa], or [byte[]] (HMAC secret) and returns a [JwtKey]
        populated per RFC 7517 / RFC 7518 with the appropriate kty and key fields.
        For asymmetric keys, only public parameters are emitted unless the supplied
        instance carries private parameters and -IncludePrivateParameters is set.

        .EXAMPLE
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        ConvertTo-JwtKey -Key $rsa

        Returns a [JwtKey] with kty='RSA' and the public n/e fields.

        .OUTPUTS
        JwtKey
    #>
    [OutputType([JwtKey])]
    [CmdletBinding()]
    param(
        # The .NET key to convert.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [object] $Key,

        # Include private key parameters in the JWK.
        [Parameter()]
        [switch] $IncludePrivateParameters,

        # Optional algorithm to record on the JWK.
        [Parameter()]
        [string] $Algorithm,

        # Optional key id to record on the JWK.
        [Parameter()]
        [string] $KeyId
    )

    process {
        $jwk = [JwtKey]::new()
        if ($PSBoundParameters.ContainsKey('Algorithm')) { $jwk.alg = $Algorithm }
        if ($PSBoundParameters.ContainsKey('KeyId')) { $jwk.kid = $KeyId }

        if ($Key -is [System.Security.Cryptography.RSA]) {
            $params = $Key.ExportParameters($IncludePrivateParameters.IsPresent)
            $jwk.kty = 'RSA'
            $jwk.n = [JwtBase64Url]::Encode($params.Modulus)
            $jwk.e = [JwtBase64Url]::Encode($params.Exponent)
            if ($IncludePrivateParameters -and $params.D) {
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
            $params = $Key.ExportParameters($IncludePrivateParameters.IsPresent)
            $jwk.kty = 'EC'
            $oidValue = $params.Curve.Oid.Value
            $oidName = $params.Curve.Oid.FriendlyName
            $jwk.crv = switch -Regex ($oidValue) {
                '^1\.2\.840\.10045\.3\.1\.7$' { 'P-256'; break }
                '^1\.3\.132\.0\.34$' { 'P-384'; break }
                '^1\.3\.132\.0\.35$' { 'P-521'; break }
                default {
                    switch ($oidName) {
                        'nistP256' { 'P-256' }
                        'ECDSA_P256' { 'P-256' }
                        'nistP384' { 'P-384' }
                        'ECDSA_P384' { 'P-384' }
                        'nistP521' { 'P-521' }
                        'ECDSA_P521' { 'P-521' }
                        default { $oidName }
                    }
                }
            }
            $jwk.x = [JwtBase64Url]::Encode($params.Q.X)
            $jwk.y = [JwtBase64Url]::Encode($params.Q.Y)
            if ($IncludePrivateParameters -and $params.D) {
                $jwk.d = [JwtBase64Url]::Encode($params.D)
            }
            return $jwk
        }

        if ($Key -is [byte[]]) {
            $jwk.kty = 'oct'
            $jwk.k = [JwtBase64Url]::Encode($Key)
            return $jwk
        }

        throw [System.ArgumentException]::new(
            "ConvertTo-JwtKey does not support a key of type [$($Key.GetType().FullName)]. " +
            'Use RSA, ECDsa, or byte[].',
            'Key'
        )
    }
}
