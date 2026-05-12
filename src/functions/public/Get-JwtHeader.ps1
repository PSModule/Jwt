function Get-JwtHeader {
    <#
        .SYNOPSIS
        Returns the parsed header of a JWT.

        .DESCRIPTION
        Parses the supplied compact JWT string (or [Jwt] object) and returns the
        [JwtHeader]. No signature verification is performed.

        .EXAMPLE
        Get-JwtHeader -Token $jwt

        Returns the typed header.

        .OUTPUTS
        JwtHeader
    #>
    [OutputType([JwtHeader])]
    [CmdletBinding()]
    param(
        # The JWT string or [Jwt] object.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [object] $Token
    )

    process {
        $parsed = ConvertFrom-Jwt -Token $Token
        return $parsed.Header
    }
}
