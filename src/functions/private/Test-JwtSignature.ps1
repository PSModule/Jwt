function Test-JwtSignature {
    <#
        .SYNOPSIS
        Verifies a JWT signature for one of the supported algorithms.

        .DESCRIPTION
        Internal verification primitive used by Test-Jwt. Assumes the algorithm-key
        compatibility check has already been done by Resolve-JwtKey.

        .EXAMPLE
        Test-JwtSignature -SigningInput $jwt.SigningInput() -Signature $jwt.Signature -Algorithm 'HS256' -ResolvedKey $hmac

        Returns $true when the signature matches.
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        # The signing input (header.payload).
        [Parameter(Mandatory)]
        [string] $SigningInput,

        # The base64url-encoded signature segment from the token.
        [Parameter()]
        [AllowEmptyString()]
        [string] $Signature,

        # The JWS algorithm.
        [Parameter(Mandatory)]
        [ValidateSet('RS256', 'HS256', 'ES256')]
        [string] $Algorithm,

        # A typed key returned by Resolve-JwtKey.
        [Parameter(Mandatory)]
        [object] $ResolvedKey
    )

    if ([string]::IsNullOrEmpty($Signature)) { return $false }

    try {
        $sigBytes = [JwtBase64Url]::Decode($Signature)
    } catch [System.FormatException] {
        return $false
    }

    $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($SigningInput)

    switch ($Algorithm) {
        'RS256' {
            $rsa = [System.Security.Cryptography.RSA] $ResolvedKey
            return $rsa.VerifyData(
                $contentBytes,
                $sigBytes,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
        }
        'HS256' {
            $hmac = [System.Security.Cryptography.HMAC] $ResolvedKey
            $computed = $hmac.ComputeHash($contentBytes)
            if ($computed.Length -ne $sigBytes.Length) { return $false }
            $diff = 0
            for ($i = 0; $i -lt $computed.Length; $i++) {
                $diff = $diff -bor ($computed[$i] -bxor $sigBytes[$i])
            }
            return $diff -eq 0
        }
        'ES256' {
            $ecdsa = [System.Security.Cryptography.ECDsa] $ResolvedKey
            return $ecdsa.VerifyData(
                $contentBytes,
                $sigBytes,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256
            )
        }
    }
    return $false
}
