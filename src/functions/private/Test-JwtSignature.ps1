function Test-JwtSignature {
    <#
        .SYNOPSIS
        Verify a JWT signature.

        .DESCRIPTION
        Verifies the signature segment of a JWT against the supplied key, using the
        algorithm declared in the header. Algorithm-key compatibility is enforced before
        any cryptographic work is performed (see RFC 7519 §10.7 and the algorithm-confusion
        attack class). Internal helper invoked by `Test-Jwt`.

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

        # The verification key.
        [Parameter(Mandatory)]
        [object] $Key
    )

    $alg = $Jwt.Header.alg
    $sigBytes = [JwtBase64Url]::Decode($Jwt.Signature)
    $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($Jwt.SigningInput())

    switch ($alg) {
        'RS256' {
            $rsa = $null
            $dispose = $false
            if ($Key -is [System.Security.Cryptography.RSA]) {
                $rsa = $Key
            } elseif ($Key -is [JwtKey]) {
                if ($Key.kty -ne 'RSA') {
                    throw "Algorithm RS256 requires an RSA key; got JwtKey with kty='$($Key.kty)'."
                }
                $rsa = ConvertFrom-JwtKey -JwtKey $Key
                $dispose = $true
            } elseif ($Key -is [string] -or $Key -is [securestring]) {
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $dispose = $true
                $pem = ConvertTo-PlainKey -Key $Key
                $rsa.ImportFromPem($pem.ToCharArray())
            } else {
                throw "Algorithm RS256 requires an RSA key, RSA PEM string, or JwtKey (kty=RSA); got [$($Key.GetType().FullName)]."
            }
            try {
                return $rsa.VerifyData(
                    $inputBytes, $sigBytes,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                )
            } finally { if ($dispose) { $rsa.Dispose() } }
        }
        'HS256' {
            if ($Key -is [System.Security.Cryptography.RSA] -or $Key -is [System.Security.Cryptography.ECDsa]) {
                throw "Algorithm HS256 requires a symmetric key; got [$($Key.GetType().FullName)]."
            }
            $secret = $null
            if ($Key -is [JwtKey]) {
                if ($Key.kty -ne 'oct') {
                    throw "Algorithm HS256 requires JwtKey with kty='oct'; got '$($Key.kty)'."
                }
                $secret = [JwtBase64Url]::Decode($Key.k)
            } elseif ($Key -is [string] -and $Key -match '-----BEGIN') {
                throw 'Algorithm HS256 requires a symmetric secret, not a PEM-encoded key (algorithm-confusion attack guard).'
            } else {
                $secret = ConvertTo-SecretBytes -Key $Key
            }
            $hmac = [System.Security.Cryptography.HMACSHA256]::new($secret)
            try {
                $computed = $hmac.ComputeHash($inputBytes)
                if ($computed.Length -ne $sigBytes.Length) { return $false }
                return [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($computed, $sigBytes)
            } finally { $hmac.Dispose() }
        }
        'ES256' {
            $ecdsa = $null
            $dispose = $false
            if ($Key -is [System.Security.Cryptography.ECDsa]) {
                $ecdsa = $Key
            } elseif ($Key -is [JwtKey]) {
                if ($Key.kty -ne 'EC') {
                    throw "Algorithm ES256 requires an EC key; got JwtKey with kty='$($Key.kty)'."
                }
                $ecdsa = ConvertFrom-JwtKey -JwtKey $Key
                $dispose = $true
            } elseif ($Key -is [string] -or $Key -is [securestring]) {
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                $dispose = $true
                $pem = ConvertTo-PlainKey -Key $Key
                $ecdsa.ImportFromPem($pem.ToCharArray())
            } else {
                throw "Algorithm ES256 requires an ECDsa key, EC PEM string, or JwtKey (kty=EC); got [$($Key.GetType().FullName)]."
            }
            try {
                return $ecdsa.VerifyData(
                    $inputBytes, $sigBytes,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256
                )
            } finally { if ($dispose) { $ecdsa.Dispose() } }
        }
        default {
            throw "Unsupported algorithm '$alg'."
        }
    }
    return $false
}
