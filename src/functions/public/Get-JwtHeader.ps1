function Get-JwtHeader {
    <#
        .SYNOPSIS
        Return the parsed header of a JWT.

        .DESCRIPTION
        Returns the typed `[JwtHeader]` object for a JWT supplied as a compact string,
        a `[securestring]`, or an existing `[Jwt]`. The signature is not verified.

        .EXAMPLE
        $tokenString | Get-JwtHeader

        Returns the parsed header.

        .OUTPUTS
        JwtHeader
    #>
    [OutputType([JwtHeader])]
    [CmdletBinding()]
    param(
        # The JWT to inspect.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object] $Token
    )

    process {
        $jwt = if ($Token -is [Jwt]) { $Token } else { ConvertFrom-Jwt -Token $Token }
        return $jwt.Header
    }
}
