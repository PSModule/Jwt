function ConvertTo-JwtKeySet {
    <#
        .SYNOPSIS
        Wraps one or more [JwtKey] objects in a [JwtKeySet] (JWKS).

        .DESCRIPTION
        Returns a [JwtKeySet] suitable for serialization with .ToJson(). Accepts JwtKey
        instances via pipeline.

        .EXAMPLE
        $jwks = $rsa, $ec | ConvertTo-JwtKey -IncludePrivateParameters | ConvertTo-JwtKeySet
        $jwks.ToJson()

        Builds a JWKS JSON document from a collection of .NET keys.

        .OUTPUTS
        JwtKeySet
    #>
    [OutputType([JwtKeySet])]
    [CmdletBinding()]
    param(
        # The JWK(s) to include in the set.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [JwtKey[]] $Key
    )

    begin {
        $accumulated = [System.Collections.Generic.List[JwtKey]]::new()
    }

    process {
        foreach ($k in $Key) { $accumulated.Add($k) }
    }

    end {
        return [JwtKeySet]::new($accumulated.ToArray())
    }
}
