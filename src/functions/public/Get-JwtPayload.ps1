function Get-JwtPayload {
    <#
        .SYNOPSIS
        Gets the decoded payload from a JWT.

        .DESCRIPTION
        Decodes and returns the JSON payload segment from a JSON Web Token. The header and signature are ignored.

        .EXAMPLE
        ```powershell
        $jwt | Get-JwtPayload
        ```

        Gets the decoded payload JSON from a JWT.

        .INPUTS
        System.String

        .OUTPUTS
        System.String

        .NOTES
        This command decodes only the payload segment and does not validate the token signature.

        .LINK
        https://github.com/SP3269/posh-jwt

        .LINK
        https://jwt.io/
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        # The JWT to read.
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Jwt
    )

    begin {}

    process {
        Write-Verbose "Processing JWT: $Jwt"
        $parts = $Jwt.Split('.')
        ConvertFrom-Base64UrlString $parts[1]
    }

    end {}
}
