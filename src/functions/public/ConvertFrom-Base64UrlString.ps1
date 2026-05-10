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
