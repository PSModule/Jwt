function ConvertFrom-Base64UrlString {
    <#
        .SYNOPSIS
        Decodes a base64url string.

        .DESCRIPTION
        Internal helper that wraps the [JwtBase64Url] class. Returns a UTF-8 string by
        default or the raw byte array when -AsByteArray is supplied.

        .EXAMPLE
        ConvertFrom-Base64UrlString 'SGVsbG8'

        Decodes the base64url string and returns the UTF-8 representation.
    #>
    [OutputType([string], [byte[]])]
    [CmdletBinding()]
    param(
        # The base64url-encoded value to decode.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [string] $InputObject,

        # Return the raw bytes instead of a UTF-8 string.
        [Parameter()]
        [switch] $AsByteArray
    )

    process {
        $bytes = [JwtBase64Url]::Decode($InputObject)
        if ($AsByteArray) { return , $bytes }
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }
}
