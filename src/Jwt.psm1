function ConvertFrom-Base64UrlString {
    <#
.SYNOPSIS
Base64url decoder.

.DESCRIPTION
Decodes base64url-encoded string to the original string or byte array.

.PARAMETER Base64UrlString
Specifies the encoded input. Mandatory string.

.PARAMETER AsByteArray
Optional switch. If specified, outputs byte array instead of string.

.INPUTS
You can pipe the string input to ConvertFrom-Base64UrlString.

.OUTPUTS
ConvertFrom-Base64UrlString returns decoded string by default, or the bytes if -AsByteArray is used.

.EXAMPLE

PS Variable:> 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' | ConvertFrom-Base64UrlString
{"alg":"RS256","typ":"JWT"}

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>
    [CmdletBinding()]
    [OutputType([string], [byte[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$Base64UrlString,
        [Parameter(Mandatory = $false)][switch]$AsByteArray
    )

    process {
        $base64String = $Base64UrlString.replace('-', '+').replace('_', '/')
        switch ($base64String.Length % 4) {
            0 { $base64String = $base64String }
            1 { $base64String = $base64String.Substring(0, $base64String.Length - 1) }
            2 { $base64String = $base64String + '==' }
            3 { $base64String = $base64String + '=' }
        }
        if ($AsByteArray) {
            [Convert]::FromBase64String($base64String)
        } else {
            [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64String))
        }
    }
}


function ConvertTo-Base64UrlString {
    <#
.SYNOPSIS
Base64url encoder.

.DESCRIPTION
Encodes a string or byte array to base64url-encoded string.

.PARAMETER in
Specifies the input. Must be string, or byte array.

.INPUTS
You can pipe the string input to ConvertTo-Base64UrlString.

.OUTPUTS
ConvertTo-Base64UrlString returns the encoded string by default.

.EXAMPLE

PS Variable:> '{"alg":"RS256","typ":"JWT"}' | ConvertTo-Base64UrlString
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$in
    )

    process {
        if ($in -is [string]) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($in)
            [Convert]::ToBase64String($bytes) -replace '\+', '-' -replace '/', '_' -replace '='
        } elseif ($in -is [byte[]]) {
            [Convert]::ToBase64String($in) -replace '\+', '-' -replace '/', '_' -replace '='
        } else {
            throw "ConvertTo-Base64UrlString requires string or byte array input, received $($in.GetType())"
        }
    }
}


function Get-JwtHeader {
    <#
.SYNOPSIS
Gets JSON payload from a JWT (JSON Web Token).

.DESCRIPTION
Decodes and extracts JSON header from JWT. Ignores payload and signature.

.PARAMETER jwt
Specifies the JWT. Mandatory string.

.INPUTS
You can pipe JWT as a string object to Get-JwtHeader.

.OUTPUTS
String. Get-JwtHeader returns decoded header part of the JWT.

.EXAMPLE

PS Variable:> $jwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJqb2UiLCJyb2xlIjoiYWRtaW4ifQ.' #gitleaks:allow
PS Variable:> Get-JwtHeader $jwt
{"alg":"none","typ":"JWT"}

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>

    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$jwt
    )

    process {
        Write-Verbose "Processing JWT: $jwt"
        $parts = $jwt.Split('.')
        ConvertFrom-Base64UrlString $parts[0]
    }
}


function Get-JwtPayload {
    <#
.SYNOPSIS
Gets JSON payload from a JWT (JSON Web Token).

.DESCRIPTION
Decodes and extracts JSON payload from JWT. Ignores headers and signature.

.PARAMETER jwt
Specifies the JWT. Mandatory string.

.INPUTS
You can pipe JWT as a string object to Get-JwtPayload.

.OUTPUTS
String. Get-JwtPayload returns decoded payload part of the JWT.

.EXAMPLE

PS Variable:> $jwt | Get-JwtPayload
{"token1":"value1","token2":"value2"}

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>

    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$jwt
    )

    process {
        Write-Verbose "Processing JWT: $jwt"
        $parts = $jwt.Split('.')
        ConvertFrom-Base64UrlString $parts[1]
    }
}


function New-Jwt {
    <#
.SYNOPSIS
Creates a JWT (JSON Web Token).

.DESCRIPTION
Creates signed JWT given a signing certificate and claims in JSON.

.PARAMETER Payload
Specifies the claim to sign in JSON. Mandatory string.

.PARAMETER Header
Specifies a JWT header. Optional. Defaults to '{"alg":"RS256","typ":"JWT"}'.

.PARAMETER Cert
Specifies the signing certificate of type System.Security.Cryptography.X509Certificates.X509Certificate2.
Must be specified and contain the private key if the algorithm in the header is RS256.

.PARAMETER Secret
Specifies the HMAC secret. Can be byte array, or a string, which will be converted to bytes.
Must be specified if the algorithm in the header is HS256.

.INPUTS
You can pipe a string object (the JSON payload) to New-Jwt.

.OUTPUTS
System.String. New-Jwt returns a string with the signed JWT.

.EXAMPLE
PS Variable:\> $cert = (Get-ChildItem Cert:\CurrentUser\My)[1]

PS Variable:\> $jwt = New-Jwt -Cert $cert -PayloadJson '{"token1":"value1","token2":"value2"}'
PS Variable:\> $jwt.Split('.').Count
3

.EXAMPLE
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("/mnt/c/PS/JWT/jwt.pfx","jwt")

$now = (Get-Date).ToUniversalTime()
$createDate = [Math]::Floor([decimal](Get-Date($now) -UFormat "%s"))
$expiryDate = [Math]::Floor([decimal](Get-Date($now.AddHours(1)) -UFormat "%s"))
$rawclaims = [Ordered]@{
    iss = "examplecom:apikey:uaqCinPt2Enb"
    iat = $createDate
    exp = $expiryDate
} | ConvertTo-Json

$jwt = New-Jwt -PayloadJson $rawclaims -Cert $cert

$apiendpoint = "https://api.example.com/api/1.0/systems"

$splat = @{
    Method="GET"
    Uri=$apiendpoint
    ContentType="application/json"
    Headers = @{authorization="bearer $jwt"}
}

Invoke-WebRequest @splat

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'New-Jwt creates an in-memory token and does not change system state.'
    )]
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)][string]$Header = '{"alg":"RS256","typ":"JWT"}',
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$PayloadJson,
        [Parameter(Mandatory = $false)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [Parameter(Mandatory = $false)]$Secret # Can be string or byte[] - checks in the code
    )

    process {
        Write-Verbose "Payload to sign: $PayloadJson"

        try {
            $Alg = (ConvertFrom-Json -InputObject $Header -ErrorAction Stop).alg
        } catch {
            throw "The supplied JWT header is not JSON: $Header"
        }
        Write-Verbose "Algorithm: $Alg"

        try {
            $null = ConvertFrom-Json -InputObject $PayloadJson -ErrorAction Stop
        } catch {
            throw "The supplied JWT payload is not JSON: $PayloadJson"
        }

        $encodedHeader = ConvertTo-Base64UrlString $Header
        $encodedPayload = ConvertTo-Base64UrlString $PayloadJson
        $jwt = $encodedHeader + '.' + $encodedPayload
        $toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)

        switch ($Alg) {
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
                            $toSign,
                            [Security.Cryptography.HashAlgorithmName]::SHA256,
                            [Security.Cryptography.RSASignaturePadding]::Pkcs1
                        )
                        $sig = ConvertTo-Base64UrlString $signature
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
                        throw "Expected Secret parameter as byte array or string, instead got $($Secret.gettype())"
                    }
                    $sig = ConvertTo-Base64UrlString $hmacsha256.ComputeHash($toSign)
                } catch {
                    throw [System.Exception]::new("Signing with HMACSHA256 failed: $_", $_.Exception)
                }
            }
            'none' {
                $sig = $null
            }
            default {
                throw 'The algorithm is not one of the supported: "RS256", "HS256", "none"'
            }
        }

        $jwt + '.' + $sig
    }
}


function Test-Jwt {
    <#
.SYNOPSIS
Tests cryptographic integrity of a JWT (JSON Web Token).

.DESCRIPTION
Verifies a digital signature of a JWT given the signing certificate (for RS256) or the secret (for HS256).

.PARAMETER Cert
Specifies the signing certificate of type System.Security.Cryptography.X509Certificates.X509Certificate2.
Must be specified if the algorithm in the header is RS256. Doesn't have to, and generally shouldn't, contain the private key.

.PARAMETER Secret
Specifies the HMAC secret. Can be byte array, or a string, which will be converted to bytes.
Must be specified if the algorithm in the header is HS256.

.INPUTS
You can pipe JWT as a string object to Test-Jwt.

.OUTPUTS
Boolean. Test-Jwt returns $true if the signature successfully verifies.

.EXAMPLE

PS Variable:> $jwt | Test-Jwt -Cert $cert
True

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>

    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$jwt,
        [Parameter(Mandatory = $false)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [Parameter(Mandatory = $false)]$Secret
    )

    process {
        Write-Verbose "Verifying JWT: $jwt"

        $parts = $jwt.Split('.')
        $header = ConvertFrom-Base64UrlString $parts[0]
        try {
            $Alg = (ConvertFrom-Json -InputObject $header -ErrorAction Stop).alg
        } catch {
            throw "The supplied JWT header is not JSON: $header"
        }
        Write-Verbose "Algorithm: $Alg"

        switch ($Alg) {
            'RS256' {
                if (-not $PSBoundParameters.ContainsKey('Cert')) {
                    throw 'RS256 requires -Cert parameter of type System.Security.Cryptography.X509Certificates.X509Certificate2'
                }
                $bytes = ConvertFrom-Base64UrlString $parts[2] -AsByteArray
                Write-Verbose "Using certificate with subject: $($Cert.Subject)"
                $SHA256 = New-Object Security.Cryptography.SHA256Managed
                $signedContent = [System.Text.Encoding]::UTF8.GetBytes($parts[0] + '.' + $parts[1])
                $computed = $SHA256.ComputeHash($signedContent)
                $cert.PublicKey.Key.VerifyHash(
                    $computed,
                    $bytes,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.RSASignaturePadding]::Pkcs1
                )
            }
            'HS256' {
                if (-not ($PSBoundParameters.ContainsKey('Secret'))) {
                    throw 'HS256 requires -Secret parameter'
                }
                $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
                if ($Secret -is [byte[]]) {
                    $hmacsha256.Key = $Secret
                } elseif ($Secret -is [string]) {
                    $hmacsha256.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
                } else {
                    throw "Expected Secret parameter as byte array or string, instead got $($Secret.gettype())"
                }
                $signedContent = [System.Text.Encoding]::UTF8.GetBytes($parts[0] + '.' + $parts[1])
                $signature = $hmacsha256.ComputeHash($signedContent)
                $encoded = ConvertTo-Base64UrlString $signature
                $encoded -eq $parts[2]
            }
            'none' {
                -not $parts[2]
            }
            default {
                throw 'The algorithm is not one of the supported: "RS256", "HS256", "none"'
            }
        }
    }

}


Set-Alias -Name 'Verify-JwtSignature' -Value 'Test-Jwt' -Description 'An alias, using non-standard verb'
Export-Member -Function '*' -Alias '*'
