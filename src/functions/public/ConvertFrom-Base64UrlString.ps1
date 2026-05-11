function ConvertFrom-Base64UrlString {
    <#
        .SYNOPSIS
        Decodes a base64url string.

        .DESCRIPTION
        Decodes a base64url-encoded string to UTF-8 text by default. Use AsByteArray to return the decoded bytes.

        .EXAMPLE
        ```powershell
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' | ConvertFrom-Base64UrlString
        ```

        Decodes the base64url value to `{"alg":"RS256","typ":"JWT"}`.

        .INPUTS
        System.String

        .OUTPUTS
        System.String
        System.Byte[]

        .NOTES
        Converts JWT-safe base64url text by restoring standard base64 characters and padding before decoding.

        .LINK
        https://psmodule.io/Jwt/Functions/ConvertFrom-Base64UrlString/

        .LINK
        https://jwt.io/
    #>
    [OutputType([string], [byte[]])]
    [CmdletBinding()]
    param(
        # The base64url-encoded string to decode.
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Base64UrlString,

        # Return decoded bytes instead of UTF-8 text.
        [Parameter()]
        [switch] $AsByteArray
    )

    begin {}

    process {
        $base64String = $Base64UrlString.Replace('-', '+').Replace('_', '/')
        switch ($base64String.Length % 4) {
            0 { }
            1 { throw [System.FormatException]::new('Invalid base64url string length.') }
            2 { $base64String = $base64String + '==' }
            3 { $base64String = $base64String + '=' }
        }
        if ($AsByteArray) {
            [Convert]::FromBase64String($base64String)
        } else {
            [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64String))
        }
    }

    end {}
}
