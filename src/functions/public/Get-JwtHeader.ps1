function Get-JwtHeader {
    <#
        .SYNOPSIS
        Gets the decoded header from a JWT.

        .DESCRIPTION
        Decodes and returns the JSON header segment from a JSON Web Token. The payload and signature are ignored.

        .EXAMPLE
        ```powershell
        $jwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJqb2UiLCJyb2xlIjoiYWRtaW4ifQ.' #gitleaks:allow
        Get-JwtHeader -Jwt $jwt
        ```

        Gets the decoded header JSON from an unsigned JWT.

        .INPUTS
        System.String

        .OUTPUTS
        System.String

        .NOTES
        This command decodes only the header segment and does not validate the token signature.

        .LINK
        https://psmodule.io/Jwt/Functions/Get-JwtHeader/

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
        if (-not $parts[0]) {
            throw [System.ArgumentException]::new('JWT header segment is missing.')
        }
        ConvertFrom-Base64UrlString $parts[0]
    }

    end {}
}
