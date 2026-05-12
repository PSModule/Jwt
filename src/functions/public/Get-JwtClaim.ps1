function Get-JwtClaim {
    <#
        .SYNOPSIS
        Returns the value of one or more claims from a JWT.

        .DESCRIPTION
        Returns the value of a named claim from the JWT payload. Supports both
        registered claims (iss, sub, aud, exp, nbf, iat, jti) and private claims
        (anything in AdditionalFields).

        Behavior:
        - A single -Name that is missing returns $null silently.
        - An array of -Name values returns an [ordered] hashtable keyed by the
          requested names. Missing names map to $null so the return shape is stable.
        - -ErrorIfMissing escalates each missing name to a non-terminating error.

        .EXAMPLE
        Get-JwtClaim -Token $jwt -Name 'sub'

        Returns the subject claim, or $null if absent.

        .EXAMPLE
        Get-JwtClaim -Token $jwt -Name 'sub','role','missing'

        Returns @{ sub = '...'; role = '...'; missing = $null }.

        .OUTPUTS
        Object
    #>
    [OutputType([object])]
    [CmdletBinding()]
    param(
        # The JWT string or [Jwt] object.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [object] $Token,

        # The claim name(s) to retrieve.
        [Parameter(Mandatory, Position = 1)]
        [string[]] $Name,

        # Emit a non-terminating error for each missing claim.
        [Parameter()]
        [switch] $ErrorIfMissing
    )

    process {
        $payload = (ConvertFrom-Jwt -Token $Token).Payload
        $registered = [JwtPayload]::RegisteredClaims

        $resolve = {
            param($claimName)
            if ($registered -contains $claimName) {
                $value = $payload.$claimName
                if ($value -is [System.Nullable[long]]) {
                    if ($value.HasValue) { return $value.Value }
                    return $null
                }
                return $value
            }
            if ($payload.AdditionalFields.ContainsKey($claimName)) {
                return $payload.AdditionalFields[$claimName]
            }
            return [System.Management.Automation.Internal.AutomationNull]::Value
        }

        if ($Name.Count -eq 1) {
            $value = & $resolve $Name[0]
            if ($value -is [System.Management.Automation.Internal.AutomationNull]) {
                if ($ErrorIfMissing) {
                    Write-Error "Claim '$($Name[0])' is not present in the JWT payload."
                }
                return $null
            }
            return $value
        }

        $result = [ordered]@{}
        foreach ($n in $Name) {
            $value = & $resolve $n
            if ($value -is [System.Management.Automation.Internal.AutomationNull]) {
                if ($ErrorIfMissing) {
                    Write-Error "Claim '$n' is not present in the JWT payload."
                }
                $result[$n] = $null
            } else {
                $result[$n] = $value
            }
        }
        return $result
    }
}
