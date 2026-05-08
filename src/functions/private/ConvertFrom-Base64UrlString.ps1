function ConvertFrom-Base64UrlString {
    <#
        .SYNOPSIS
        Decode a Base64URL string.

        .DESCRIPTION
        Decodes a Base64URL string (RFC 4648 §5). Returns the raw bytes by default, or a
        UTF-8 string when `-AsString` is passed. Internal helper used by the JWT pipeline.

        .EXAMPLE
        ConvertFrom-Base64UrlString -Value 'aGVsbG8' -AsString

        Returns "hello".

        .OUTPUTS
        System.Byte[] or System.String
    #>
    [OutputType([byte[]], [string])]
    [CmdletBinding()]
    param(
        # The Base64URL value to decode.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string] $Value,

        # Decode the result as a UTF-8 string instead of returning raw bytes.
        [Parameter()]
        [switch] $AsString
    )

    process {
        if ($AsString) {
            return [JwtBase64Url]::DecodeString($Value)
        }
        return , [JwtBase64Url]::Decode($Value)
    }
}
