function ConvertFrom-Jwt {
    <#
        .SYNOPSIS
        Parse a compact JWT string into a typed [Jwt] object.

        .DESCRIPTION
        Accepts a compact JWT string (`header.payload.signature`) and returns a populated
        `[Jwt]` object. The signature is not verified. Malformed input (wrong segment count,
        invalid Base64URL, invalid JSON, or empty header/payload) raises a terminating error.

        Pipeline-friendly: `Get-Content token.txt | ConvertFrom-Jwt`.

        .EXAMPLE
        ```powershell
        $jwt = $tokenString | ConvertFrom-Jwt
        $jwt.Header
        $jwt.Payload
        ```

        Parses a token without verifying it.

        .OUTPUTS
        Jwt
    #>
    [OutputType([Jwt])]
    [CmdletBinding()]
    param(
        # The compact JWT string to parse.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object] $Token
    )

    process {
        $tokenString = if ($Token -is [securestring]) {
            ConvertTo-PlainKey -Key $Token
        } elseif ($Token -is [Jwt]) {
            return $Token
        } else {
            [string]$Token
        }

        if ([string]::IsNullOrWhiteSpace($tokenString)) {
            throw 'JWT string is null or empty.'
        }

        $segments = $tokenString.Split('.')
        if ($segments.Count -ne 3) {
            throw "JWT must contain exactly 3 segments separated by '.', got $($segments.Count)."
        }

        $encodedHeader = $segments[0]
        $encodedPayload = $segments[1]
        $signature = $segments[2]

        if ([string]::IsNullOrEmpty($encodedHeader)) { throw 'JWT header segment is empty.' }
        if ([string]::IsNullOrEmpty($encodedPayload)) { throw 'JWT payload segment is empty.' }

        try { $headerJson = [JwtBase64Url]::DecodeString($encodedHeader) }
        catch { throw "JWT header is not valid Base64URL: $($_.Exception.Message)" }
        try { $payloadJson = [JwtBase64Url]::DecodeString($encodedPayload) }
        catch { throw "JWT payload is not valid Base64URL: $($_.Exception.Message)" }

        try { $headerObj = ConvertFrom-Json -InputObject $headerJson -AsHashtable -Depth 100 }
        catch { throw "JWT header is not valid JSON: $($_.Exception.Message)" }
        try { $payloadObj = ConvertFrom-Json -InputObject $payloadJson -AsHashtable -Depth 100 }
        catch { throw "JWT payload is not valid JSON: $($_.Exception.Message)" }

        if ($null -eq $headerObj) { throw 'JWT header decoded to null.' }
        if ($null -eq $payloadObj) { throw 'JWT payload decoded to null.' }

        $jwtHeader = [JwtHeader]::new([hashtable]$headerObj)
        $jwtPayload = [JwtPayload]::new([hashtable]$payloadObj)

        $jwt = [Jwt]::new()
        $jwt.Header = $jwtHeader
        $jwt.Payload = $jwtPayload
        $jwt.EncodedHeader = $encodedHeader
        $jwt.EncodedPayload = $encodedPayload
        $jwt.Signature = $signature
        return $jwt
    }
}
