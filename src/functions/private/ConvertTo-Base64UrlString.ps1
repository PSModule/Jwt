function ConvertTo-Base64UrlString {
    <#
        .SYNOPSIS
        Encode a byte array or string to Base64URL.

        .DESCRIPTION
        Encodes the input to Base64URL (RFC 4648 §5) without padding.
        Internal helper used by the JWT pipeline.

        .EXAMPLE
        ConvertTo-Base64UrlString -Bytes ([System.Text.Encoding]::UTF8.GetBytes('hello'))

        Returns the Base64URL encoding of the UTF-8 bytes for "hello".

        .OUTPUTS
        System.String
    #>
    [OutputType([string])]
    [CmdletBinding(DefaultParameterSetName = 'Bytes')]
    param(
        # Raw bytes to encode.
        [Parameter(Mandatory, ParameterSetName = 'Bytes', Position = 0, ValueFromPipeline)]
        [byte[]] $Bytes,

        # UTF-8 string to encode.
        [Parameter(Mandatory, ParameterSetName = 'Text', Position = 0, ValueFromPipeline)]
        [string] $Text
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Text') {
            return [JwtBase64Url]::EncodeString($Text)
        }
        return [JwtBase64Url]::Encode($Bytes)
    }
}
