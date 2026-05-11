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
        https://psmodule.io/Jwt/Functions/Get-JwtPayload/

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
        Write-Verbose "Processing JWT with length $($Jwt.Length) characters"
        $parts = $Jwt.Split('.')
        if ($parts.Count -ne 3) {
            throw [System.ArgumentException]::new('JWT must have exactly 3 segments.')
        }
        if (-not $parts[1]) {
            throw [System.ArgumentException]::new('JWT payload segment is missing.')
        }
        ConvertFrom-Base64UrlString $parts[1]
    }

    end {}
}
