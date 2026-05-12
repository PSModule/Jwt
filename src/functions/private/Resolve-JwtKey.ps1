function Resolve-JwtKey {
    <#
        .SYNOPSIS
        Resolves a -Key parameter into a typed .NET key for a given JWS algorithm.

        .DESCRIPTION
        Performs the algorithm-key compatibility check required by Test-Jwt and New-Jwt
        before any signing or verification work. Rejects mismatched key types (e.g.,
        an RSA public key supplied for an HS256 token) with a terminating error to
        block algorithm-confusion attacks.

        .EXAMPLE
        Resolve-JwtKey -Algorithm 'RS256' -Key $rsaPem

        Returns an [RSA] populated from the PEM-encoded key.
    #>
    [OutputType([object])]
    [CmdletBinding()]
    param(
        # The algorithm declared by the JWT header.
        [Parameter(Mandatory)]
        [ValidateSet('RS256', 'HS256', 'ES256', 'none')]
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

    if ($Key -is [JwtKey]) {
        switch ($Algorithm) {
            'RS256' {
                if ($Key.kty -ne 'RSA') {
                    throw [System.ArgumentException]::new(
                        "Algorithm RS256 requires a JwtKey with kty='RSA'. Got kty='$($Key.kty)'.",
                        'Key'
                    )
                }
                return (ConvertFrom-JwtKey -Key $Key)
            }
            'HS256' {
                if ($Key.kty -ne 'oct') {
                    throw [System.ArgumentException]::new(
                        "Algorithm HS256 requires a JwtKey with kty='oct'. Got kty='$($Key.kty)'.",
                        'Key'
                    )
                }
                return (ConvertFrom-JwtKey -Key $Key)
            }
            'ES256' {
                if ($Key.kty -ne 'EC') {
                    throw [System.ArgumentException]::new(
                        "Algorithm ES256 requires a JwtKey with kty='EC'. Got kty='$($Key.kty)'.",
                        'Key'
                    )
                }
                return (ConvertFrom-JwtKey -Key $Key)
            }
        }
    }

    switch ($Algorithm) {
        'RS256' {
            if ($Key -is [System.Security.Cryptography.RSA]) { return $Key }
            if ($Key -is [string]) {
                if ($Key -notmatch '-----BEGIN [A-Z ]*KEY-----') {
                    throw [System.ArgumentException]::new(
                        'Algorithm RS256 requires a PEM-encoded RSA key string. The supplied string is not PEM.',
                        'Key'
                    )
                }
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $rsa.ImportFromPem($Key)
                return $rsa
            }
            throw [System.ArgumentException]::new(
                "Algorithm RS256 does not accept a key of type [$($Key.GetType().FullName)]. " +
                'Use an RSA instance, a PEM string, or a JwtKey with kty=RSA.',
                'Key'
            )
        }
        'HS256' {
            if ($Key -is [byte[]]) { return [System.Security.Cryptography.HMACSHA256]::new($Key) }
            if ($Key -is [string]) {
                if ($Key -match '-----BEGIN [A-Z ]*KEY-----') {
                    throw [System.ArgumentException]::new(
                        'Algorithm HS256 rejected a PEM-encoded key. HS256 is symmetric and requires a raw secret. ' +
                        'This blocks the classic HS256-with-RSA-public-key algorithm-confusion attack.',
                        'Key'
                    )
                }
                return [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($Key))
            }
            throw [System.ArgumentException]::new(
                "Algorithm HS256 does not accept a key of type [$($Key.GetType().FullName)]. " +
                'Use a byte[], a raw secret string/SecureString, or a JwtKey with kty=oct.',
                'Key'
            )
        }
        'ES256' {
            if ($Key -is [System.Security.Cryptography.ECDsa]) { return $Key }
            if ($Key -is [string]) {
                if ($Key -notmatch '-----BEGIN [A-Z ]*KEY-----') {
                    throw [System.ArgumentException]::new(
                        'Algorithm ES256 requires a PEM-encoded EC key string. The supplied string is not PEM.',
                        'Key'
                    )
                }
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                $ecdsa.ImportFromPem($Key)
                return $ecdsa
            }
            throw [System.ArgumentException]::new(
                "Algorithm ES256 does not accept a key of type [$($Key.GetType().FullName)]. " +
                'Use an ECDsa instance, a PEM string, or a JwtKey with kty=EC.',
                'Key'
            )
        }
    }

    throw [System.NotSupportedException]::new("Algorithm '$Algorithm' is not supported.")
}
