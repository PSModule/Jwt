function Resolve-JwtKey {
    <#
        .SYNOPSIS
        Resolves a -Key parameter into a typed .NET key for a given JWS algorithm.

        .DESCRIPTION
        Performs the algorithm-key compatibility check required by Test-Jwt and New-Jwt
        before any signing or verification work. Rejects mismatched key types (e.g.,
        an RSA public key supplied for an HS256 token) with a terminating error to
        block algorithm-confusion attacks.

        Supports all JWS algorithms registered in RFC 7518 §3:
        HS256/HS384/HS512, RS256/RS384/RS512, ES256/ES384/ES512, PS256/PS384/PS512, none.

        .EXAMPLE
        Resolve-JwtKey -Algorithm 'RS256' -Key $rsaPem

        Returns an [RSA] populated from the PEM-encoded key.
    #>
    [OutputType([object])]
    [CmdletBinding()]
    param(
        # The algorithm declared by the JWT header.
        [Parameter(Mandatory)]
        [ValidateSet(
            'HS256', 'HS384', 'HS512',
            'RS256', 'RS384', 'RS512',
            'ES256', 'ES384', 'ES512',
            'PS256', 'PS384', 'PS512',
            'none'
        )]
        [string] $Algorithm,

        # The key material. Acceptable shapes depend on $Algorithm.
        [Parameter()]
        [object] $Key
    )

    if ($Algorithm -eq 'none') {
        if ($null -ne $Key) {
            throw [System.ArgumentException]::new(
                "Algorithm 'none' does not accept a key. Remove -Key or pass a non-'none' algorithm.",
                'Key'
            )
        }
        return $null
    }

    if ($null -eq $Key) {
        throw [System.ArgumentException]::new("Algorithm '$Algorithm' requires a -Key value.", 'Key')
    }

    if ($Key -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
        try {
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $Key = $plain
    }

    $family = switch -Regex ($Algorithm) {
        '^HS' { 'HS' }
        '^RS' { 'RSA' }
        '^PS' { 'RSA' }
        '^ES' { 'EC' }
    }

    $expectedCurve = switch ($Algorithm) {
        'ES256' { 'P-256' }
        'ES384' { 'P-384' }
        'ES512' { 'P-521' }
        default { $null }
    }

    $expectedCurveOid = switch ($Algorithm) {
        'ES256' { '1.2.840.10045.3.1.7' }
        'ES384' { '1.3.132.0.34' }
        'ES512' { '1.3.132.0.35' }
        default { $null }
    }

    if ($Key -is [JwtKey]) {
        switch ($family) {
            'RSA' {
                if ($Key.kty -ne 'RSA') {
                    throw [System.ArgumentException]::new(
                        "Algorithm $Algorithm requires a JwtKey with kty='RSA'. Got kty='$($Key.kty)'.",
                        'Key'
                    )
                }
                return (ConvertFrom-JwtKey -Key $Key)
            }
            'HS' {
                if ($Key.kty -ne 'oct') {
                    throw [System.ArgumentException]::new(
                        "Algorithm $Algorithm requires a JwtKey with kty='oct'. Got kty='$($Key.kty)'.",
                        'Key'
                    )
                }
                $bytes = [JwtBase64Url]::Decode($Key.k)
                return (New-JwtHmac -Algorithm $Algorithm -KeyBytes $bytes)
            }
            'EC' {
                if ($Key.kty -ne 'EC') {
                    throw [System.ArgumentException]::new(
                        "Algorithm $Algorithm requires a JwtKey with kty='EC'. Got kty='$($Key.kty)'.",
                        'Key'
                    )
                }
                if ($Key.crv -ne $expectedCurve) {
                    throw [System.ArgumentException]::new(
                        "Algorithm $Algorithm requires a JwtKey with crv='$expectedCurve'. Got crv='$($Key.crv)'.",
                        'Key'
                    )
                }
                return (ConvertFrom-JwtKey -Key $Key)
            }
        }
    }

    switch ($family) {
        'RSA' {
            if ($Key -is [System.Security.Cryptography.RSA]) { return $Key }
            if ($Key -is [string]) {
                if ($Key -notmatch '-----BEGIN [A-Z ]*KEY-----') {
                    throw [System.ArgumentException]::new(
                        "Algorithm $Algorithm requires a PEM-encoded RSA key string. The supplied string is not PEM.",
                        'Key'
                    )
                }
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $rsa.ImportFromPem($Key)
                return $rsa
            }
            throw [System.ArgumentException]::new(
                "Algorithm $Algorithm does not accept a key of type [$($Key.GetType().FullName)]. " +
                'Use an RSA instance, a PEM string, or a JwtKey with kty=RSA.',
                'Key'
            )
        }
        'HS' {
            if ($Key -is [byte[]]) { return (New-JwtHmac -Algorithm $Algorithm -KeyBytes $Key) }
            if ($Key -is [string]) {
                if ($Key -match '-----BEGIN [A-Z ]*KEY-----') {
                    throw [System.ArgumentException]::new(
                        "Algorithm $Algorithm rejected a PEM-encoded key. $Algorithm is symmetric and requires a raw secret. " +
                        'This blocks the classic HS+RSA-public-key algorithm-confusion attack.',
                        'Key'
                    )
                }
                return (New-JwtHmac -Algorithm $Algorithm -KeyBytes ([System.Text.Encoding]::UTF8.GetBytes($Key)))
            }
            throw [System.ArgumentException]::new(
                "Algorithm $Algorithm does not accept a key of type [$($Key.GetType().FullName)]. " +
                'Use a byte[], a raw secret string/SecureString, or a JwtKey with kty=oct.',
                'Key'
            )
        }
        'EC' {
            if ($Key -is [System.Security.Cryptography.ECDsa]) {
                $params = $Key.ExportParameters($false)
                $oid = $params.Curve.Oid.Value
                if ($oid -and $oid -ne $expectedCurveOid) {
                    throw [System.ArgumentException]::new(
                        "Algorithm $Algorithm requires curve $expectedCurve (OID $expectedCurveOid). The supplied ECDsa key uses OID $oid.",
                        'Key'
                    )
                }
                return $Key
            }
            if ($Key -is [string]) {
                if ($Key -notmatch '-----BEGIN [A-Z ]*KEY-----') {
                    throw [System.ArgumentException]::new(
                        "Algorithm $Algorithm requires a PEM-encoded EC key string. The supplied string is not PEM.",
                        'Key'
                    )
                }
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                $ecdsa.ImportFromPem($Key)
                $params = $ecdsa.ExportParameters($false)
                $oid = $params.Curve.Oid.Value
                if ($oid -and $oid -ne $expectedCurveOid) {
                    $ecdsa.Dispose()
                    throw [System.ArgumentException]::new(
                        "Algorithm $Algorithm requires curve $expectedCurve (OID $expectedCurveOid). The supplied EC PEM uses OID $oid.",
                        'Key'
                    )
                }
                return $ecdsa
            }
            throw [System.ArgumentException]::new(
                "Algorithm $Algorithm does not accept a key of type [$($Key.GetType().FullName)]. " +
                'Use an ECDsa instance, a PEM string, or a JwtKey with kty=EC.',
                'Key'
            )
        }
    }

    throw [System.NotSupportedException]::new("Algorithm '$Algorithm' is not supported.")
}
