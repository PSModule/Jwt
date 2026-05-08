function Add-JwtLocalSignature {
    <#
        .SYNOPSIS
        Signs a JWT using a local RSA private key (RS256).

        .DESCRIPTION
        Takes an unsigned [Jwt] object, computes an RS256 signature over its signing input
        (header.payload) using the supplied PEM-encoded RSA private key, and returns the same
        [Jwt] object with the Signature property populated.

        .EXAMPLE
        ```powershell
        Add-JwtLocalSignature -Jwt $unsigned -PrivateKey (Get-Content key.pem -Raw)
        ```

        Signs the unsigned JWT with the PEM-encoded RSA private key.

        .OUTPUTS
        Jwt
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Function mutates the in-memory [Jwt] object only'
    )]
    [CmdletBinding()]
    [OutputType([Jwt])]
    param(
        # The unsigned [Jwt] object to sign.
        [Parameter(Mandatory)]
        [Jwt] $Jwt,

        # The RSA private key in PEM format. Accepts a [string] or a [securestring].
        [Parameter(Mandatory)]
        [object] $PrivateKey
    )

    process {
        if ($PrivateKey -is [securestring]) {
            $PrivateKey = $PrivateKey | ConvertFrom-SecureString -AsPlainText
        }

        $rsa = [System.Security.Cryptography.RSA]::Create()
        try {
            $rsa.ImportFromPem([string]$PrivateKey)
            $signatureBytes = $rsa.SignData(
                [System.Text.Encoding]::UTF8.GetBytes($Jwt.SigningInput()),
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $Jwt.Signature = [JwtBase64Url]::Encode($signatureBytes)
            return $Jwt
        } finally {
            if ($rsa) { $rsa.Dispose() }
        }
    }
}
