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
