function ConvertFrom-Jwt {
    <#
        .SYNOPSIS
        Parses a compact JWT string into a typed [Jwt] object.

        .DESCRIPTION
        Splits a JWT into its three segments, decodes the header and payload, and
        returns a [Jwt] object that round-trips back to the original encoded form
        (the parsed segments are kept verbatim). No signature verification is
        performed — use Test-Jwt for that.

        .EXAMPLE
        $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2UifQ.sig' | ConvertFrom-Jwt

        Parses the token and returns a [Jwt] object.

        .OUTPUTS
        Jwt
    #>
    [OutputType([Jwt])]
    [CmdletBinding()]
    param(
        # The compact JWT string. Pipeline-bound.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [object] $Token
    )

    process {
        $tokenString = if ($Token -is [Jwt]) { $Token.ToString() }
        elseif ($Token -is [System.Security.SecureString]) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
            try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        } else { [string]$Token }

        $parts = $tokenString.Split('.')
        if ($parts.Count -ne 3) {
            throw [System.FormatException]::new(
                "JWT must have exactly 3 segments separated by '.'. Got $($parts.Count)."
            )
        }
        if ([string]::IsNullOrEmpty($parts[0])) {
            throw [System.FormatException]::new('JWT header segment is empty.')
        }
        if ([string]::IsNullOrEmpty($parts[1])) {
            throw [System.FormatException]::new('JWT payload segment is empty.')
        }

        try { $headerJson = [JwtBase64Url]::DecodeString($parts[0]) }
        catch [System.FormatException] {
            throw [System.FormatException]::new('JWT header segment contains invalid base64url characters.')
        }
        try { $payloadJson = [JwtBase64Url]::DecodeString($parts[1]) }
        catch [System.FormatException] {
            throw [System.FormatException]::new('JWT payload segment contains invalid base64url characters.')
        }

        try { $headerHash = ConvertFrom-Json -InputObject $headerJson -AsHashtable -Depth 100 -ErrorAction Stop }
        catch { throw [System.FormatException]::new('JWT header segment is not valid JSON.') }
        try { $payloadHash = ConvertFrom-Json -InputObject $payloadJson -AsHashtable -Depth 100 -ErrorAction Stop }
        catch { throw [System.FormatException]::new('JWT payload segment is not valid JSON.') }

        if ($null -eq $headerHash) {
            throw [System.FormatException]::new('JWT header segment decoded to null.')
        }
        if ($null -eq $payloadHash) {
            throw [System.FormatException]::new('JWT payload segment decoded to null.')
        }

        $jwtHeader = [JwtHeader]::new($headerHash)
        $jwtPayload = [JwtPayload]::new($payloadHash)
        return [Jwt]::new($jwtHeader, $jwtPayload, $parts[2], $parts[0], $parts[1])
    }
}
