function New-Jwt {
    <#
        .SYNOPSIS
        Create a new JSON Web Token (JWT).

        .DESCRIPTION
        Builds a JWT from header overrides and a claims hashtable. By default the token is
        signed with the supplied `-Key` using the requested `-Algorithm`. With `-Unsigned`,
        the token is returned with an empty signature so the signing step can be performed
        externally (for example via Azure Key Vault, an HSM, or another remote signer); the
        consumer assigns `$jwt.Signature` after computing the signature against
        `$jwt.SigningInput()`.

        Supported algorithms: RS256 (RSA + SHA-256, PKCS#1 v1.5), HS256 (HMAC + SHA-256),
        ES256 (ECDSA P-256 + SHA-256). All `ConvertTo-Json` calls use `-Depth 100 -Compress`
        and emit from `[ordered]` dictionaries so signatures verify deterministically.

        .EXAMPLE
        $pem = Get-Content ./private.pem -Raw
        $jwt = New-Jwt -Payload @{ iss = 'app'; sub = 'svc'; exp = 1800000000 } -Key $pem -Algorithm RS256
        $jwt.ToString()

        Creates a signed RS256 JWT.

        .EXAMPLE
        $jwt = New-Jwt -Payload @{ iss = 'app' } -Unsigned
        $jwt.SigningInput()  # send to external signer
        $jwt.Signature = $externalBase64UrlSignature
        $jwt.ToString()

        Builds an unsigned token, then attaches an externally computed signature.

        .OUTPUTS
        Jwt
    #>
    [OutputType([Jwt])]
    [CmdletBinding(DefaultParameterSetName = 'Signed', SupportsShouldProcess)]
    param(
        # Optional header overrides. `alg` and `typ` are set automatically; pass `kid` or
        # custom JOSE fields here.
        [Parameter()]
        [hashtable] $Header = @{},

        # The JWT claims. Registered claims (iss, sub, aud, exp, nbf, iat, jti) are recognized;
        # everything else flows through as private claims.
        [Parameter(Mandatory)]
        [hashtable] $Payload,

        # Signing key. RSA PEM string (or [securestring] wrapping a PEM) for RS256;
        # EC PEM string for ES256; [byte[]], raw secret [string], or [securestring] for HS256.
        [Parameter(Mandatory, ParameterSetName = 'Signed')]
        [object] $Key,

        # Produce an unsigned token. The signature must be attached externally.
        [Parameter(Mandatory, ParameterSetName = 'Unsigned')]
        [switch] $Unsigned,

        # Signing algorithm. Stored in the header regardless of whether the token is signed.
        [Parameter()]
        [ValidateSet('RS256', 'HS256', 'ES256')]
        [string] $Algorithm = 'RS256'
    )

    process {
        if (-not $PSCmdlet.ShouldProcess('JWT', 'Create')) { return }

        $headerCopy = @{}
        foreach ($k in $Header.Keys) { $headerCopy[$k] = $Header[$k] }
        $headerCopy['alg'] = $Algorithm
        if (-not $headerCopy.ContainsKey('typ')) { $headerCopy['typ'] = 'JWT' }

        $jwtHeader = [JwtHeader]::new($headerCopy)
        $jwtPayload = [JwtPayload]::new($Payload)
        $jwt = [Jwt]::new($jwtHeader, $jwtPayload)

        if ($Unsigned) { return $jwt }

        $signingInput = $jwt.SigningInput()
        $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($signingInput)
        $sigBytes = $null

        switch ($Algorithm) {
            'RS256' {
                $rsa = [System.Security.Cryptography.RSA]::Create()
                try {
                    $pem = ConvertTo-PlainKey -Key $Key
                    $rsa.ImportFromPem($pem.ToCharArray())
                    $sigBytes = $rsa.SignData(
                        $inputBytes,
                        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                    )
                } finally { $rsa.Dispose() }
            }
            'HS256' {
                $secret = ConvertTo-SecretBytes -Key $Key
                $hmac = [System.Security.Cryptography.HMACSHA256]::new($secret)
                try { $sigBytes = $hmac.ComputeHash($inputBytes) } finally { $hmac.Dispose() }
            }
            'ES256' {
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                try {
                    $pem = ConvertTo-PlainKey -Key $Key
                    $ecdsa.ImportFromPem($pem.ToCharArray())
                    $sigBytes = $ecdsa.SignData(
                        $inputBytes,
                        [System.Security.Cryptography.HashAlgorithmName]::SHA256
                    )
                } finally { $ecdsa.Dispose() }
            }
        }

        $jwt.Signature = [JwtBase64Url]::Encode($sigBytes)
        return $jwt
    }
}
