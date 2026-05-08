function Test-JwtClaim {
    <#
        .SYNOPSIS
        Validate the registered claims of a JWT.

        .DESCRIPTION
        Performs the registered-claim checks defined by RFC 7519 §4.1: `exp`, `nbf`, `iat`,
        `iss`, and `aud`. Returns an array of check result hashtables, one per check, in a
        stable order so callers can index by `Name`.
        Internal helper invoked by `Test-Jwt`.

        .EXAMPLE
        Test-JwtClaim -Payload $jwt.Payload -Issuer 'https://example.com' -Audience 'api'

        Returns the per-check result list.

        .OUTPUTS
        System.Collections.Hashtable[]
    #>
    [OutputType([hashtable[]])]
    [CmdletBinding()]
    param(
        # The payload to validate.
        [Parameter(Mandatory)]
        [JwtPayload] $Payload,

        # Expected issuer; if supplied, the token `iss` must match.
        [Parameter()]
        [string] $Issuer,

        # Expected audience(s); validation passes if at least one matches the token `aud`.
        [Parameter()]
        [string[]] $Audience,

        # Permitted clock drift for `exp`/`nbf` checks.
        [Parameter()]
        [timespan] $ClockSkew = ([timespan]::Zero),

        # Require an `exp` claim to be present.
        [Parameter()]
        [bool] $RequireExpiration = $true
    )

    $now = [DateTimeOffset]::UtcNow
    $skewSeconds = [long]$ClockSkew.TotalSeconds
    $checks = [System.Collections.Generic.List[hashtable]]::new()

    if ($null -eq $Payload.exp) {
        if ($RequireExpiration) {
            $checks.Add(@{ Name = 'Expiration'; Passed = $false; Reason = "Token has no 'exp' claim." })
        } else {
            $checks.Add(@{ Name = 'Expiration'; Passed = $true; Reason = $null })
        }
    } else {
        $expTime = [DateTimeOffset]::FromUnixTimeSeconds([long]$Payload.exp)
        if (($now - $expTime).TotalSeconds -gt $skewSeconds) {
            $checks.Add(@{ Name = 'Expiration'; Passed = $false; Reason = "Token expired at $($expTime.ToString('o'))" })
        } else {
            $checks.Add(@{ Name = 'Expiration'; Passed = $true; Reason = $null })
        }
    }

    if ($null -eq $Payload.nbf) {
        $checks.Add(@{ Name = 'NotBefore'; Passed = $true; Reason = $null })
    } else {
        $nbfTime = [DateTimeOffset]::FromUnixTimeSeconds([long]$Payload.nbf)
        if (($nbfTime - $now).TotalSeconds -gt $skewSeconds) {
            $checks.Add(@{ Name = 'NotBefore'; Passed = $false; Reason = "Token not valid before $($nbfTime.ToString('o'))" })
        } else {
            $checks.Add(@{ Name = 'NotBefore'; Passed = $true; Reason = $null })
        }
    }

    if ($PSBoundParameters.ContainsKey('Issuer') -and -not [string]::IsNullOrEmpty($Issuer)) {
        if ([string]::Equals($Payload.iss, $Issuer, [System.StringComparison]::Ordinal)) {
            $checks.Add(@{ Name = 'Issuer'; Passed = $true; Reason = $null })
        } else {
            $checks.Add(@{ Name = 'Issuer'; Passed = $false; Reason = "Issuer mismatch: expected '$Issuer', got '$($Payload.iss)'." })
        }
    } else {
        $checks.Add(@{ Name = 'Issuer'; Passed = $true; Reason = $null })
    }

    if ($PSBoundParameters.ContainsKey('Audience') -and $null -ne $Audience -and $Audience.Count -gt 0) {
        $tokenAud = @()
        if ($null -ne $Payload.aud) {
            if ($Payload.aud -is [string]) { $tokenAud = @($Payload.aud) }
            elseif ($Payload.aud -is [System.Collections.IEnumerable]) { $tokenAud = @($Payload.aud) }
            else { $tokenAud = @([string]$Payload.aud) }
        }
        $matched = $false
        foreach ($a in $Audience) {
            foreach ($t in $tokenAud) {
                if ([string]::Equals([string]$t, $a, [System.StringComparison]::Ordinal)) { $matched = $true; break }
            }
            if ($matched) { break }
        }
        if ($matched) {
            $checks.Add(@{ Name = 'Audience'; Passed = $true; Reason = $null })
        } else {
            $expected = $Audience -join ', '
            $actual = $tokenAud -join ', '
            $reason = "Audience mismatch: expected one of [$expected], got [$actual]."
            $checks.Add(@{ Name = 'Audience'; Passed = $false; Reason = $reason })
        }
    } else {
        $checks.Add(@{ Name = 'Audience'; Passed = $true; Reason = $null })
    }

    return $checks.ToArray()
}
