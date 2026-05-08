function Get-JwtClaim {
    <#
        .SYNOPSIS
        Get the value of one or more claims from a JWT.

        .DESCRIPTION
        Reads claims from a JWT payload. Accepts both registered claims (`iss`, `sub`, `aud`,
        `exp`, `nbf`, `iat`, `jti`) and private claims that live on `AdditionalFields`.

        With a single `-Name`, returns the value (or `$null` if missing).
        With an array of names, returns an `[ordered]` hashtable keyed by the requested
        names; missing names map to `$null`. With `-ErrorIfMissing`, missing names emit a
        non-terminating error per missing name.

        .EXAMPLE
        $tokenString | Get-JwtClaim -Name iss

        Returns the issuer claim.

        .EXAMPLE
        $tokenString | Get-JwtClaim -Name iss, sub, scope

        Returns an ordered hashtable with the three claim values.

        .OUTPUTS
        System.Object or System.Collections.Specialized.OrderedDictionary
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'ErrorIfMissing',
        Justification = 'Used inside scriptblock $getOne'
    )]
    [OutputType([object])]
    [CmdletBinding()]
    param(
        # The JWT to read from.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object] $Token,

        # The name(s) of the claim(s) to read.
        [Parameter(Mandatory, Position = 1)]
        [string[]] $Name,

        # Emit a non-terminating error for each missing name instead of returning `$null`.
        [Parameter()]
        [switch] $ErrorIfMissing
    )

    process {
        $jwt = if ($Token -is [Jwt]) { $Token } else { ConvertFrom-Jwt -Token $Token }
        $payload = $jwt.Payload

        $getOne = {
            param([string] $claimName)
            if ([JwtPayload]::RegisteredClaims -contains $claimName) {
                $value = $payload.$claimName
                if ($null -eq $value) {
                    if ($ErrorIfMissing) { Write-Error "Claim '$claimName' is not present in the token." }
                }
                return $value
            }
            if ($null -ne $payload.AdditionalFields -and $payload.AdditionalFields.ContainsKey($claimName)) {
                return $payload.AdditionalFields[$claimName]
            }
            if ($ErrorIfMissing) { Write-Error "Claim '$claimName' is not present in the token." }
            return $null
        }

        if ($Name.Count -eq 1) {
            return & $getOne $Name[0]
        }

        $result = [ordered]@{}
        foreach ($n in $Name) { $result[$n] = & $getOne $n }
        return $result
    }
}
