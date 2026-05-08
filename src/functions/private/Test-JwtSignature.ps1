function Test-JwtSignature {
    <#
        .SYNOPSIS
        Verify a JWT signature.

        .DESCRIPTION
        Verifies the signature segment of a JWT against the supplied key using the algorithm
        declared in the token header. Algorithm-key compatibility is enforced before any
        cryptographic work is performed to block algorithm-confusion attacks.

        Supported algorithms:
          HMAC     — HS256, HS384, HS512
          RSA      — RS256, RS384, RS512 (PKCS#1 v1.5)
          RSA-PSS  — PS256, PS384, PS512
          ECDSA    — ES256, ES384, ES512

        Internal helper invoked by `Test-Jwt`.

        .EXAMPLE
        Test-JwtSignature -Jwt $jwt -Key $publicPem

        Returns `$true` if the signature is valid.

        .OUTPUTS
        System.Boolean
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        # The parsed `[Jwt]` to verify.
        [Parameter(Mandatory)]
        [Jwt] $Jwt,

        # The verification key. Type must match the algorithm in the token header.
        [Parameter(Mandatory)]
        [object] $Key
    )

    $alg = $Jwt.Header.alg
    $sigBytes = [JwtBase64Url]::Decode($Jwt.Signature)
    $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($Jwt.SigningInput())

    $hashAlg = switch -Wildcard ($alg) {
        '*256' { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
        '*384' { [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
        '*512' { [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
        default { [System.Security.Cryptography.HashAlgorithmName]::new() }
    }

    switch -Regex ($alg) {
        '^(RS|PS)' {
            $padding = if ($alg -like 'RS*') {
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            } else {
                [System.Security.Cryptography.RSASignaturePadding]::Pss
            }
            $rsa = $null
            $dispose = $false
            if ($Key -is [System.Security.Cryptography.RSA]) {
                $rsa = $Key
            } elseif ($Key -is [JwtKey]) {
                if ($Key.kty -ne 'RSA') { throw "Algorithm $alg requires an RSA key; got JwtKey with kty='$($Key.kty)'." }
                $rsa = ConvertFrom-JwtKey -JwtKey $Key
                $dispose = $true
            } elseif ($Key -is [string] -or $Key -is [securestring]) {
                $pem = ConvertTo-PlainKey -Key $Key
                if ($pem -notmatch '-----BEGIN') { throw "Algorithm $alg requires an RSA PEM key string." }
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $dispose = $true
                $rsa.ImportFromPem($pem.ToCharArray())
            } else {
                throw "Algorithm $alg requires an RSA key, RSA PEM string, or JwtKey (kty=RSA); got [$($Key.GetType().FullName)]."
            }
            try { return $rsa.VerifyData($inputBytes, $sigBytes, $hashAlg, $padding) }
            finally { if ($dispose) { $rsa.Dispose() } }
        }
        '^HS' {
            if ($Key -is [System.Security.Cryptography.RSA] -or
                $Key -is [System.Security.Cryptography.ECDsa]) {
                throw "Algorithm $alg requires a symmetric key; got [$($Key.GetType().FullName)]."
            }
            $secret = $null
            if ($Key -is [JwtKey]) {
                if ($Key.kty -ne 'oct') { throw "Algorithm $alg requires JwtKey with kty='oct'; got '$($Key.kty)'." }
                $secret = [JwtBase64Url]::Decode($Key.k)
            } elseif ($Key -is [string] -and $Key -match '-----BEGIN') {
                throw "Algorithm $alg requires a symmetric secret, not a PEM-encoded key (algorithm-confusion attack guard)."
            } else {
                $secret = ConvertTo-SecretByte -Key $Key
            }
            $hmac = switch ($alg) {
                'HS256' { [System.Security.Cryptography.HMACSHA256]::new($secret) }
                'HS384' { [System.Security.Cryptography.HMACSHA384]::new($secret) }
                'HS512' { [System.Security.Cryptography.HMACSHA512]::new($secret) }
            }
            try {
                $computed = $hmac.ComputeHash($inputBytes)
                if ($computed.Length -ne $sigBytes.Length) { return $false }
                return [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($computed, $sigBytes)
            } finally { $hmac.Dispose() }
        }
        '^ES' {
            $ecdsa = $null
            $dispose = $false
            if ($Key -is [System.Security.Cryptography.ECDsa]) {
                $ecdsa = $Key
            } elseif ($Key -is [JwtKey]) {
                if ($Key.kty -ne 'EC') { throw "Algorithm $alg requires an EC key; got JwtKey with kty='$($Key.kty)'." }
                $ecdsa = ConvertFrom-JwtKey -JwtKey $Key
                $dispose = $true
            } elseif ($Key -is [string] -or $Key -is [securestring]) {
                $pem = ConvertTo-PlainKey -Key $Key
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                $dispose = $true
                $ecdsa.ImportFromPem($pem.ToCharArray())
            } else {
                throw "Algorithm $alg requires an ECDsa key, EC PEM string, or JwtKey (kty=EC); got [$($Key.GetType().FullName)]."
            }
            try { return $ecdsa.VerifyData($inputBytes, $sigBytes, $hashAlg) }
            finally { if ($dispose) { $ecdsa.Dispose() } }
        }
        default { throw "Unsupported algorithm '$alg'." }
    }
    return $false
}
