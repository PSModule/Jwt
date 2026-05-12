function ConvertFrom-JwtKeySet {
    <#
        .SYNOPSIS
        Parses a JWK Set (JWKS) JSON string into a [JwtKeySet].

        .DESCRIPTION
        Accepts a JWKS JSON document per RFC 7517 §5 and returns a typed [JwtKeySet]
        containing the parsed [JwtKey] entries. Unknown top-level fields are preserved
        in AdditionalFields.

        .EXAMPLE
        $set = ConvertFrom-JwtKeySet -Json (Invoke-RestMethod 'https://issuer/.well-known/jwks.json' | ConvertTo-Json -Depth 10 -Compress)

        Parses a JWKS retrieved from a discovery endpoint.

        .OUTPUTS
        JwtKeySet
    #>
    [OutputType([JwtKeySet])]
    [CmdletBinding()]
    param(
        # The JWKS JSON document.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string] $Json
    )

    process {
        $parsed = $Json | ConvertFrom-Json -AsHashtable -Depth 100
        if ($parsed -isnot [System.Collections.IDictionary]) {
            throw [System.ArgumentException]::new('JWKS JSON must be a JSON object.', 'Json')
        }
        if (-not $parsed.Contains('keys')) {
            throw [System.ArgumentException]::new("JWKS JSON is missing the required 'keys' member (RFC 7517 §5.1).", 'Json')
        }
        return [JwtKeySet]::new($parsed)
    }
}
