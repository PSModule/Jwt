function Test-Jwt {
    <#
        .SYNOPSIS
        Tests the cryptographic integrity of a JWT.

        .DESCRIPTION
        Verifies a JWT signature using the signing certificate for RS256 or a shared secret for HS256. Tokens using the
        none algorithm are valid only when the signature segment is empty.

        .EXAMPLE
        ```powershell
        $jwt | Test-Jwt -Secret 'a-string-secret-at-least-256-bits-long'
        ```

        Tests an HS256 JWT with a shared secret.

        .EXAMPLE
        ```powershell
        $jwt | Test-Jwt -Cert $cert
        ```

        Tests an RS256 JWT with a public certificate.

        .INPUTS
        System.String

        .OUTPUTS
        System.Boolean

        .NOTES
        The Verify-JwtSignature alias is preserved for compatibility with the original module command surface.

        .LINK
        https://psmodule.io/Jwt/Functions/Test-Jwt/

        .LINK
        https://jwt.io/
    #>
    [OutputType([bool])]
    [Alias('Verify-JwtSignature')]
    [CmdletBinding()]
    param(
        # The JWT to test.
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Jwt,

        # The certificate to use for RS256 signature verification.
        [Parameter()]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert,

        # The string or byte array secret to use for HS256 signature verification.
        [Parameter()]
        [ValidateNotNull()]
        [object] $Secret
    )

    begin {}

    process {
        Write-Verbose "Verifying JWT with length $($Jwt.Length) characters"

        $parts = $Jwt.Split('.')
        if ($parts.Count -ne 3) {
            throw [System.ArgumentException]::new('JWT must have exactly 3 segments.')
        }
        if (-not $parts[0]) {
            throw [System.ArgumentException]::new('JWT header segment is missing.')
        }
        if (-not $parts[1]) {
            throw [System.ArgumentException]::new('JWT payload segment is missing.')
        }
        $header = ConvertFrom-Base64UrlString $parts[0]
        try {
            $algorithm = (ConvertFrom-Json -InputObject $header -ErrorAction Stop).alg
        } catch {
            throw [System.FormatException]::new("The supplied JWT header segment is not valid JSON. Header length: $($header.Length) characters.")
        }
        Write-Verbose "Algorithm: $algorithm"

        switch ($algorithm) {
            'RS256' {
                if (-not $PSBoundParameters.ContainsKey('Cert')) {
                    throw 'RS256 requires -Cert parameter of type System.Security.Cryptography.X509Certificates.X509Certificate2'
                }
                if ([string]::IsNullOrEmpty($parts[2])) {
                    return $false
                }
                $bytes = ConvertFrom-Base64UrlString $parts[2] -AsByteArray
                Write-Verbose "Using certificate with subject: $($Cert.Subject)"
                $signedContent = [System.Text.Encoding]::UTF8.GetBytes($parts[0] + '.' + $parts[1])
                $computed = [System.Security.Cryptography.SHA256]::HashData($signedContent)
                $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Cert)
                if ($null -eq $rsa) {
                    throw "There's no RSA public key in the supplied certificate - cannot verify"
                }
                try {
                    $rsa.VerifyHash(
                        $computed,
                        $bytes,
                        [Security.Cryptography.HashAlgorithmName]::SHA256,
                        [Security.Cryptography.RSASignaturePadding]::Pkcs1
                    )
                } finally {
                    $rsa.Dispose()
                }
            }
            'HS256' {
                if (-not ($PSBoundParameters.ContainsKey('Secret'))) {
                    throw 'HS256 requires -Secret parameter'
                }
                if ($Secret -isnot [byte[]] -and $Secret -isnot [string]) {
                    throw [System.ArgumentException]::new("Expected Secret parameter as byte array or string, instead got $($Secret.GetType())")
                }
                $hmacsha256 = [System.Security.Cryptography.HMACSHA256]::new()
                try {
                    $hmacsha256.Key = if ($Secret -is [byte[]]) { $Secret } else { [System.Text.Encoding]::UTF8.GetBytes($Secret) }
                    $signedContent = [System.Text.Encoding]::UTF8.GetBytes($parts[0] + '.' + $parts[1])
                    $signature = $hmacsha256.ComputeHash($signedContent)
                    if (-not $parts[2]) {
                        $false
                    } else {
                        try {
                            $providedSignature = ConvertFrom-Base64UrlString $parts[2] -AsByteArray
                        } catch [System.FormatException] {
                            $providedSignature = $null
                        }
                        if ($null -eq $providedSignature -or $signature.Length -ne $providedSignature.Length) {
                            $false
                        } else {
                            $difference = 0
                            for ($index = 0; $index -lt $signature.Length; $index++) {
                                $difference = $difference -bor ($signature[$index] -bxor $providedSignature[$index])
                            }
                            $difference -eq 0
                        }
                    }
                } finally {
                    $hmacsha256.Dispose()
                }
            }
            'none' {
                $parts[2] -eq ''
            }
            default {
                throw 'The algorithm is not one of the supported: "RS256", "HS256", "none"'
            }
        }
    }

    end {}
}
