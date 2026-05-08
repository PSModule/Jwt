function ConvertTo-PlainKey {
    <#
        .SYNOPSIS
        Convert a key parameter into a plain string.

        .DESCRIPTION
        Accepts either a [string] or a [securestring] and returns the underlying plain text.
        Internal helper used to normalize PEM key inputs before importing them into
        cryptographic providers.

        .EXAMPLE
        ConvertTo-PlainKey -Key $secureStringPem

        Returns the PEM as a plain string.

        .OUTPUTS
        System.String
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        # The key value to normalize.
        [Parameter(Mandatory, Position = 0)]
        [object] $Key
    )

    if ($Key -is [securestring]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    if ($Key -is [string]) { return [string]$Key }
    throw "Key must be a [string] or [securestring]; got [$($Key.GetType().FullName)]."
}
