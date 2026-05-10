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
        https://github.com/SP3269/posh-jwt

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
        Write-Verbose "Payload to sign: $PayloadJson"

        try {
            $algorithm = (ConvertFrom-Json -InputObject $Header -ErrorAction Stop).alg
        } catch {
            throw "The supplied JWT header is not JSON: $Header"
        }
        Write-Verbose "Algorithm: $algorithm"

        try {
            $null = ConvertFrom-Json -InputObject $PayloadJson -ErrorAction Stop
        } catch {
            throw "The supplied JWT payload is not JSON: $PayloadJson"
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
                $rsa = $Cert.PrivateKey
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
                        $message = "Signing with SHA256 and Pkcs1 padding failed using private key $($rsa): $_"
                        throw [System.Exception]::new($message, $_.Exception)
                    }
                }
            }
            'HS256' {
                if (-not ($PSBoundParameters.ContainsKey('Secret'))) {
                    throw 'HS256 requires -Secret parameter'
                }
                try {
                    $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
                    if ($Secret -is [byte[]]) {
                        $hmacsha256.Key = $Secret
                    } elseif ($Secret -is [string]) {
                        $hmacsha256.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
                    } else {
                        throw "Expected Secret parameter as byte array or string, instead got $($Secret.GetType())"
                    }
                    $encodedSignature = ConvertTo-Base64UrlString $hmacsha256.ComputeHash($contentBytes)
                } catch {
                    throw [System.Exception]::new("Signing with HMACSHA256 failed: $_", $_.Exception)
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
