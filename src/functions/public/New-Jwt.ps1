function New-Jwt {
    <#
        .SYNOPSIS
        Creates a JSON Web Token.

        .DESCRIPTION
        Creates a JWT from JSON header and payload strings. Supports RS256 with a signing certificate, HS256 with a
        shared secret, and the none algorithm.

        .EXAMPLE
        ```powershell
        $payload = '{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}'
        $secret = 'a-string-secret-at-least-256-bits-long'

        New-Jwt -Header '{"alg":"HS256","typ":"JWT"}' -PayloadJson $payload -Secret $secret
        ```

        Creates an HS256-signed JWT.

        .EXAMPLE
        ```powershell
        $cert = (Get-ChildItem Cert:\CurrentUser\My)[1]
        $jwt = New-Jwt -Cert $cert -PayloadJson '{"token1":"value1","token2":"value2"}'
        $jwt.Split('.').Count
        ```

        Creates an RS256-signed JWT with a certificate private key and returns the number of JWT segments.

        .INPUTS
        System.String

        .OUTPUTS
        System.String

        .NOTES
        RS256 requires a certificate with a private key. HS256 requires a string or byte array secret.

        .LINK
        https://psmodule.io/Jwt/Functions/New-Jwt/

        .LINK
        https://jwt.io/
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'New-Jwt creates an in-memory token and does not change system state.'
    )]
    [OutputType([string])]
    [CmdletBinding()]
    param(
        # The JWT header JSON.
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Header = '{"alg":"RS256","typ":"JWT"}',

        # The JWT payload JSON.
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $PayloadJson,

        # The signing certificate to use for RS256 tokens.
        [Parameter()]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert,

        # The string or byte array secret to use for HS256 tokens.
        [Parameter()]
        [ValidateNotNull()]
        [object] $Secret
    )

    begin {}

    process {
        Write-Verbose "Payload to sign length: $($PayloadJson.Length) characters"

        try {
            $algorithm = (ConvertFrom-Json -InputObject $Header -ErrorAction Stop).alg
        } catch {
            throw [System.FormatException]::new("The supplied JWT header is not valid JSON. Header length: $($Header.Length) characters.")
        }
        Write-Verbose "Algorithm: $algorithm"

        try {
            $null = ConvertFrom-Json -InputObject $PayloadJson -ErrorAction Stop
        } catch {
            throw [System.FormatException]::new("The supplied JWT payload is not valid JSON. Payload length: $($PayloadJson.Length) characters.")
        }

        $encodedHeader = ConvertTo-Base64UrlString $Header
        $encodedPayload = ConvertTo-Base64UrlString $PayloadJson
        $jwtContent = $encodedHeader + '.' + $encodedPayload
        $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($jwtContent)

        switch ($algorithm) {
            'RS256' {
                if (-not $PSBoundParameters.ContainsKey('Cert')) {
                    throw 'RS256 requires -Cert parameter of type System.Security.Cryptography.X509Certificates.X509Certificate2'
                }
                Write-Verbose "Signing certificate: $($Cert.Subject)"
                $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
                if ($null -eq $rsa) {
                    throw "There's no private key in the supplied certificate - cannot sign"
                } else {
                    try {
                        $signature = $rsa.SignData(
                            $contentBytes,
                            [Security.Cryptography.HashAlgorithmName]::SHA256,
                            [Security.Cryptography.RSASignaturePadding]::Pkcs1
                        )
                        $encodedSignature = ConvertTo-Base64UrlString $signature
                    } catch {
                        $message = "Signing with SHA256 and Pkcs1 padding failed using the certificate private key: $_"
                        throw [System.Exception]::new($message, $_.Exception)
                    } finally {
                        $rsa.Dispose()
                    }
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
                    $encodedSignature = ConvertTo-Base64UrlString $hmacsha256.ComputeHash($contentBytes)
                } catch {
                    throw [System.Exception]::new("Signing with HMACSHA256 failed: $_", $_.Exception)
                } finally {
                    $hmacsha256.Dispose()
                }
            }
            'none' {
                $encodedSignature = $null
            }
            default {
                throw 'The algorithm is not one of the supported: "RS256", "HS256", "none"'
            }
        }

        $jwtContent + '.' + $encodedSignature
    }

    end {}
}
