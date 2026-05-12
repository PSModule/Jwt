function ConvertTo-Base64UrlString {
    <#
        .SYNOPSIS
        Encodes text or bytes as a base64url string.

        .DESCRIPTION
        Encodes a string or byte array using base64url encoding suitable for JWT headers, payloads, and signatures.

        .EXAMPLE
        ```powershell
        '{"alg":"RS256","typ":"JWT"}' | ConvertTo-Base64UrlString
        ```

        Encodes the JWT header JSON as `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9`.

        .INPUTS
        System.String
        System.Byte[]

        .OUTPUTS
        System.String

        .NOTES
        Converts standard base64 output to JWT-safe base64url text by replacing URL-sensitive
        characters and removing padding.

        .LINK
        https://psmodule.io/Jwt/Functions/ConvertTo-Base64UrlString/

        .LINK
        https://jwt.io/
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        # The string or byte array to encode.
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [ValidateNotNull()]
        [Alias('in')]
        [object] $InputObject
    )

    begin {}

    process {
        if ($InputObject -is [string]) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputObject)
            [Convert]::ToBase64String($bytes) -replace '\+', '-' -replace '/', '_' -replace '='
        } elseif ($InputObject -is [byte[]]) {
            [Convert]::ToBase64String($InputObject) -replace '\+', '-' -replace '/', '_' -replace '='
        } else {
            $type = $InputObject.GetType()
            $message = "ConvertTo-Base64UrlString requires string or byte array input, received $type"
            throw [System.ArgumentException]::new($message, 'InputObject')
        }
    }

    end {}
}
