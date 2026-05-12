function Test-JwtClaim {
    <#
        .SYNOPSIS
        Validates the registered claims of a JWT payload against a set of constraints.

        .DESCRIPTION
        Internal helper used by Test-Jwt. Returns an array of check result hashtables
        with Name, Passed, and Reason fields. Audience matching is array-aware per
        RFC 7519 §4.1.3.
    #>
    [OutputType([hashtable[]])]
    [CmdletBinding()]
    param(
        # The payload to validate.
        [Parameter(Mandatory)]
        [JwtPayload] $Payload,

        # Expected issuer.
        [Parameter()]
        [string] $Issuer,

        # Accepted audiences.
        [Parameter()]
        [string[]] $Audience,

        # Allowed clock skew.
        [Parameter()]
        [timespan] $ClockSkew = [timespan]::Zero,

        # Require an exp claim to be present.
        [Parameter()]
        [bool] $RequireExpiration = $true,

        # The reference time. Defaults to UtcNow.
        [Parameter()]
        [datetime] $Now = [datetime]::UtcNow
    )

    $checks = @()
    $skewSec = [long]$ClockSkew.TotalSeconds
    $nowSec = [DateTimeOffset]::new($Now.ToUniversalTime()).ToUnixTimeSeconds()

    if ($null -ne $Payload.exp) {
        $expVal = [long]$Payload.exp
        if ($nowSec -gt ($expVal + $skewSec)) {
            $expAt = [DateTimeOffset]::FromUnixTimeSeconds($expVal).UtcDateTime.ToString('o')
            $checks += @{ Name = 'Expiration'; Passed = $false; Reason = "Token expired at $expAt." }
        } else {
            $checks += @{ Name = 'Expiration'; Passed = $true; Reason = $null }
        }
    } else {
        if ($RequireExpiration) {
            $checks += @{ Name = 'Expiration'; Passed = $false; Reason = "Token has no 'exp' claim." }
        } else {
            $checks += @{ Name = 'Expiration'; Passed = $true; Reason = $null }
        }
    }

    if ($null -ne $Payload.nbf) {
        $nbfVal = [long]$Payload.nbf
        if ($nowSec -lt ($nbfVal - $skewSec)) {
            $nbfAt = [DateTimeOffset]::FromUnixTimeSeconds($nbfVal).UtcDateTime.ToString('o')
            $checks += @{ Name = 'NotBefore'; Passed = $false; Reason = "Token not valid before $nbfAt." }
        } else {
            $checks += @{ Name = 'NotBefore'; Passed = $true; Reason = $null }
        }
    } else {
        $checks += @{ Name = 'NotBefore'; Passed = $true; Reason = $null }
    }

    if ($PSBoundParameters.ContainsKey('Issuer')) {
        if ($Payload.iss -cne $Issuer) {
            $checks += @{ Name = 'Issuer'; Passed = $false; Reason = "Issuer '$($Payload.iss)' does not match expected '$Issuer'." }
        } else {
            $checks += @{ Name = 'Issuer'; Passed = $true; Reason = $null }
        }
    } else {
        $checks += @{ Name = 'Issuer'; Passed = $true; Reason = $null }
    }

    if ($PSBoundParameters.ContainsKey('Audience')) {
        $tokenAud = $Payload.aud
        $tokenAudList = if ($tokenAud -is [array]) { @($tokenAud | ForEach-Object { [string]$_ }) }
        elseif ($null -eq $tokenAud) { @() }
        else { @([string]$tokenAud) }

        $matched = $false
        foreach ($a in $Audience) {
            if ($tokenAudList -ccontains $a) { $matched = $true; break }
        }
        if ($matched) {
            $checks += @{ Name = 'Audience'; Passed = $true; Reason = $null }
        } else {
            $checks += @{ Name = 'Audience'; Passed = $false; Reason = "None of the supplied audiences matched the token's 'aud' claim." }
        }
    } else {
        $checks += @{ Name = 'Audience'; Passed = $true; Reason = $null }
    }

    return , $checks
}
