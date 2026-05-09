function New-Jwt {
    <#
        .SYNOPSIS
        Create a new JSON Web Token (JWT).

        .DESCRIPTION
        Builds a JWT from header overrides and a claims hashtable. By default the token is
        signed with the supplied `-Key` using the requested `-Algorithm`. With `-Unsigned`,
        the token is returned with an empty signature so the signing step can be performed
        externally (Azure Key Vault, an HSM, a remote signing service, etc.).

        Supported algorithms:
          HMAC     — HS256, HS384, HS512
          RSA      — RS256, RS384, RS512 (PKCS#1 v1.5)
          RSA-PSS  — PS256, PS384, PS512
          ECDSA    — ES256 (P-256), ES384 (P-384), ES512 (P-521)

        All `ConvertTo-Json` calls use `-Depth 100 -Compress` and emit from `[ordered]`
        dictionaries so signatures verify deterministically.

        .EXAMPLE
        ```powershell
        $pem = Get-Content ./private.pem -Raw
        $jwt = New-Jwt -Payload @{ iss = 'app'; sub = 'svc'; exp = 1800000000 } -Key $pem -Algorithm RS256
        $jwt.ToString()
        ```

        Creates a signed RS256 JWT.

        .EXAMPLE
        ```powershell
        $jwt = New-Jwt -Payload @{ iss = 'app' } -Unsigned -Algorithm RS256
        $jwt.SigningInput()  # send to external signer
        $jwt.Signature = $externalBase64UrlSignature
        $jwt.ToString()
        ```

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

        # Signing key. Type must match the algorithm:
        #   HS256/HS384/HS512 — [byte[]], [string], or [securestring] (UTF-8 secret)
        #   RS256/RS384/RS512/PS256/PS384/PS512 — RSA PEM [string] or [securestring]
        #   ES256/ES384/ES512 — EC PEM [string] or [securestring]
        [Parameter(Mandatory, ParameterSetName = 'Signed')]
        [object] $Key,

        # Produce an unsigned token. The signature must be attached externally.
        [Parameter(Mandatory, ParameterSetName = 'Unsigned')]
        [switch] $Unsigned,

        # Signing algorithm. Stored in the header regardless of whether the token is signed.
        [Parameter()]
        [ValidateSet('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512')]
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

        $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($jwt.SigningInput())

        $hashAlg = switch -Wildcard ($Algorithm) {
            '*256' { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
            '*384' { [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
            '*512' { [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
            default { [System.Security.Cryptography.HashAlgorithmName]::new() }
        }

        $sigBytes = $null

        switch -Regex ($Algorithm) {
            '^RS' {
                $rsa = [System.Security.Cryptography.RSA]::Create()
                try {
                    $rsa.ImportFromPem((ConvertTo-PlainKey -Key $Key).ToCharArray())
                    $sigBytes = $rsa.SignData($inputBytes, $hashAlg, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                } finally { $rsa.Dispose() }
                break
            }
            '^PS' {
                $rsa = [System.Security.Cryptography.RSA]::Create()
                try {
                    $rsa.ImportFromPem((ConvertTo-PlainKey -Key $Key).ToCharArray())
                    $sigBytes = $rsa.SignData($inputBytes, $hashAlg, [System.Security.Cryptography.RSASignaturePadding]::Pss)
                } finally { $rsa.Dispose() }
                break
            }
            '^HS' {
                $secret = ConvertTo-SecretByte -Key $Key
                $hmac = switch ($Algorithm) {
                    'HS256' { [System.Security.Cryptography.HMACSHA256]::new($secret) }
                    'HS384' { [System.Security.Cryptography.HMACSHA384]::new($secret) }
                    'HS512' { [System.Security.Cryptography.HMACSHA512]::new($secret) }
                }
                try { $sigBytes = $hmac.ComputeHash($inputBytes) } finally { $hmac.Dispose() }
                break
            }
            '^ES' {
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                try {
                    $ecdsa.ImportFromPem((ConvertTo-PlainKey -Key $Key).ToCharArray())
                    $sigBytes = $ecdsa.SignData($inputBytes, $hashAlg)
                } finally { $ecdsa.Dispose() }
                break
            }
        }


        $jwt.Signature = [JwtBase64Url]::Encode($sigBytes)
        return $jwt
    }
}
