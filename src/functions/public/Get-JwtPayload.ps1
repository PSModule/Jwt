function Get-JwtPayload {
    <#
        .SYNOPSIS
        Return the parsed payload of a JWT.

        .DESCRIPTION
        Returns the typed `[JwtPayload]` object for a JWT supplied as a compact string,
        a `[securestring]`, or an existing `[Jwt]`. The signature is not verified.

        .EXAMPLE
        $tokenString | Get-JwtPayload

        Returns the parsed payload.

        .OUTPUTS
        JwtPayload
    #>
    [OutputType([JwtPayload])]
    [CmdletBinding()]
    param(
        # The JWT to inspect.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object] $Token
    )

    process {
        $jwt = if ($Token -is [Jwt]) { $Token } else { ConvertFrom-Jwt -Token $Token }
        return $jwt.Payload
    }
}
