function ConvertTo-Base64UrlString {
    <#
        .SYNOPSIS
        Encodes a string or byte array as base64url.

        .DESCRIPTION
        Internal helper that wraps the [JwtBase64Url] class and produces an unpadded
        base64url string per RFC 4648 §5.

        .EXAMPLE
        ConvertTo-Base64UrlString 'Hello'

        Encodes the UTF-8 bytes of the string as base64url.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        # The value to encode. Accepts a [string] (UTF-8 encoded) or a [byte[]].
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [object] $InputObject
    )

    process {
        if ($InputObject -is [byte[]]) {
            return [JwtBase64Url]::Encode($InputObject)
        }
        if ($InputObject -is [string]) {
            return [JwtBase64Url]::EncodeString($InputObject)
        }
        throw [System.ArgumentException]::new(
            "ConvertTo-Base64UrlString requires string or byte array input. Got [$($InputObject.GetType().FullName)].",
            'InputObject'
        )
    }
}
