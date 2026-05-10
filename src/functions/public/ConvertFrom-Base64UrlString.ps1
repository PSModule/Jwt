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
        https://github.com/SP3269/posh-jwt

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

    end {}
}
