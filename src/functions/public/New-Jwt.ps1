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
