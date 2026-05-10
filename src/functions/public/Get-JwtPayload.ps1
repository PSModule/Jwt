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
