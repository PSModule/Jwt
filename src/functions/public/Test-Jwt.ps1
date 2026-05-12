function Test-Jwt {
    <#
        .SYNOPSIS
        Verifies the signature and claims of a JWT.

        .DESCRIPTION
        Performs the full JWT validation pipeline:

        1. Algorithm-key compatibility check (blocks the HS256-with-RSA-public-key
           algorithm-confusion attack and unknown alg values).
        2. Signature verification.
        3. Registered claim validation (exp, nbf, iss, aud), with -ClockSkew tolerance.

        Returns $true / $false by default. With -Detailed, returns a [pscustomobject]
        whose Checks property is a stable, ordered array indexable by Name.

        Unsigned tokens (alg=none) are rejected unless -AllowUnsigned is supplied.
        When -AllowUnsigned is used, claim validation still runs and -Detailed
        reports SignatureValidated=$false with Reason='Skipped (unsigned token)'.

        .EXAMPLE
        $jwt | Test-Jwt -Key $secret

        Verifies an HS256 token.

        .EXAMPLE
        Test-Jwt -Token $jwt -Key $rsa -Issuer 'https://issuer' -Audience 'api' -Detailed

        Returns a structured validation report.

        .OUTPUTS
        System.Boolean
        System.Management.Automation.PSCustomObject
    #>
    [OutputType([bool], [pscustomobject])]
    [CmdletBinding()]
    param(
        # The JWT to validate.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [object] $Token,

        # The verification key. Format depends on the token's alg.
        [Parameter()]
        [object] $Key,

        # Expected issuer.
        [Parameter()]
        [string] $Issuer,

        # Accepted audiences (any-match).
        [Parameter()]
        [string[]] $Audience,

        # Allowed clock skew for exp / nbf checks.
        [Parameter()]
        [timespan] $ClockSkew = [timespan]::Zero,

        # Require an exp claim. Defaults to $true.
        [Parameter()]
        [bool] $RequireExpiration = $true,

        # Allow alg=none unsigned tokens.
        [Parameter()]
        [switch] $AllowUnsigned,

        # Return a structured report instead of [bool].
        [Parameter()]
        [switch] $Detailed
    )

    process {
        $parsed = ConvertFrom-Jwt -Token $Token
        $alg = $parsed.Header.alg

        $algCheck = @{ Name = 'Algorithm'; Passed = $true; Reason = $null }
        $sigCheck = @{ Name = 'Signature'; Passed = $false; Reason = $null }
        $signatureValidated = $false

        if ([string]::IsNullOrEmpty($alg)) {
            $algCheck.Passed = $false
            $algCheck.Reason = "JWT header is missing the 'alg' claim."
            throw [System.Security.Authentication.AuthenticationException]::new($algCheck.Reason)
        }

        if ($alg -eq 'none') {
            if (-not $AllowUnsigned) {
                $algCheck.Passed = $false
                $algCheck.Reason = "Algorithm 'none' rejected. Pass -AllowUnsigned to permit unsigned tokens."
                throw [System.Security.Authentication.AuthenticationException]::new($algCheck.Reason)
            }
            if ($PSBoundParameters.ContainsKey('Key')) {
                $algCheck.Passed = $false
                $algCheck.Reason = "Algorithm 'none' does not accept a key."
                throw [System.ArgumentException]::new($algCheck.Reason, 'Key')
            }
            $sigCheck.Passed = $true
            $sigCheck.Reason = 'Skipped (unsigned token)'
            $signatureValidated = $false
        } elseif ($alg -in @('RS256', 'HS256', 'ES256')) {
            $resolved = Resolve-JwtKey -Algorithm $alg -Key $Key
            try {
                $sigOk = Test-JwtSignature `
                    -SigningInput $parsed.SigningInput() `
                    -Signature $parsed.Signature `
                    -Algorithm $alg `
                    -ResolvedKey $resolved
            } finally {
                if ($resolved -is [System.IDisposable] -and $Key -isnot [System.Security.Cryptography.RSA] -and $Key -isnot [System.Security.Cryptography.ECDsa]) {
                    $resolved.Dispose()
                }
            }
            if ($sigOk) {
                $sigCheck.Passed = $true
                $signatureValidated = $true
            } else {
                $sigCheck.Reason = 'Signature verification failed.'
            }
        } else {
            $algCheck.Passed = $false
            $algCheck.Reason = "Algorithm '$alg' is not supported. Allowed: RS256, HS256, ES256, none."
            throw [System.Security.Authentication.AuthenticationException]::new($algCheck.Reason)
        }

        $claimArgs = @{ Payload = $parsed.Payload; ClockSkew = $ClockSkew; RequireExpiration = $RequireExpiration }
        if ($PSBoundParameters.ContainsKey('Issuer')) { $claimArgs['Issuer'] = $Issuer }
        if ($PSBoundParameters.ContainsKey('Audience')) { $claimArgs['Audience'] = $Audience }
        $claimChecks = Test-JwtClaim @claimArgs

        $checks = @($algCheck, $sigCheck) + $claimChecks
        $valid = -not ($checks | Where-Object { -not $_.Passed })

        if ($Detailed) {
            return [pscustomobject]@{
                Valid              = [bool]$valid
                SignatureValidated = $signatureValidated
                Algorithm          = $alg
                Checks             = $checks
            }
        }
        return [bool]$valid
    }
}
