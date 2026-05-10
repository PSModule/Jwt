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
    [Alias('Verify-JwtSignature')]
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
