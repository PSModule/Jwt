function Get-JwtPayload {
    <#
        .SYNOPSIS
        Returns the parsed payload of a JWT.

        .DESCRIPTION
        Parses the supplied compact JWT string (or [Jwt] object) and returns the
        [JwtPayload]. No signature verification is performed.

        .EXAMPLE
        Get-JwtPayload -Token $jwt

        Returns the typed payload.

        .OUTPUTS
        JwtPayload
    #>
    [OutputType([JwtPayload])]
    [CmdletBinding()]
    param(
        # The JWT string or [Jwt] object.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [object] $Token
    )

    process {
        $parsed = ConvertFrom-Jwt -Token $Token
        return $parsed.Payload
    }
}
