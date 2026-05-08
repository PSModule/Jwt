function ConvertTo-SecretBytes {
    <#
        .SYNOPSIS
        Convert an HMAC secret parameter into a byte array.

        .DESCRIPTION
        Accepts a [byte[]], [string], or [securestring] and returns the secret as bytes
        suitable for HMAC operations. Strings are encoded as UTF-8.
        Internal helper used by HS256 signing and verification.

        .EXAMPLE
        ConvertTo-SecretBytes -Key 'topsecret'

        Returns the UTF-8 byte representation of the string.

        .OUTPUTS
        System.Byte[]
    #>
    [OutputType([byte[]])]
    [CmdletBinding()]
    param(
        # The secret value to normalize to bytes.
        [Parameter(Mandatory, Position = 0)]
        [object] $Key
    )

    if ($Key -is [byte[]]) { return [byte[]]$Key }
    if ($Key -is [securestring]) {
        $plain = ConvertTo-PlainKey -Key $Key
        return [System.Text.Encoding]::UTF8.GetBytes($plain)
    }
    if ($Key -is [string]) { return [System.Text.Encoding]::UTF8.GetBytes([string]$Key) }
    throw "HMAC key must be [byte[]], [string], or [securestring]; got [$($Key.GetType().FullName)]."
}
