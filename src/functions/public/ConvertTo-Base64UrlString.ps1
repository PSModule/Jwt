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
