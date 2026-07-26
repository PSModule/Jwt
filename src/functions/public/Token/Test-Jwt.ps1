function Test-Jwt {
    <#
        .SYNOPSIS
        Verifies the signature and claims of a JWT.

        .DESCRIPTION
        Performs the full JWT validation pipeline:

        1. Algorithm-key compatibility check (blocks the HS256-with-RSA-public-key
           algorithm-confusion attack and unknown alg values).
        2. Signature verification.
        3. Registered claim validation (exp, nbf, iat, iss, aud), with -ClockSkew tolerance.

        Returns $true / $false by default. With -Detailed, returns a [pscustomobject]
        whose Checks property is a stable, ordered array indexable by Name.

        Parameter sets steer validation mode:
        - SignedValidation: requires -Key and validates signed algorithms.
        - UnsignedValidation: requires -AllowUnsigned and only permits alg=none.

        Unsigned tokens (alg=none) are rejected unless -AllowUnsigned is supplied.
        When -AllowUnsigned is used, claim validation still runs and -Detailed
        reports SignatureValidated=$false with Reason='Skipped (unsigned token)'.

        .EXAMPLE
        $jwt | Test-Jwt -Key $secret

        Verifies an HS256 token.

        .EXAMPLE
        Test-Jwt -Token $jwt -Key $rsa -Issuer 'https://issuer' -Audience 'api' -Detailed

        Returns a structured validation report.
        .LINK
        https://psmodule.io/Jwt/Functions/Token/Test-Jwt/

        .OUTPUTS
        System.Boolean
        System.Management.Automation.PSCustomObject
    #>
    [OutputType([bool], [pscustomobject])]
    [CmdletBinding(DefaultParameterSetName = 'SignedValidation')]
    param(
        # The JWT to validate.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = 'SignedValidation')]
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = 'UnsignedValidation')]
        [ValidateNotNull()]
        [object] $Token,

        # The verification key. Format depends on the token's alg.
        [Parameter(Mandatory, ParameterSetName = 'SignedValidation')]
        [object] $Key,

        # Expected issuer.
        [Parameter(ParameterSetName = 'SignedValidation')]
        [Parameter(ParameterSetName = 'UnsignedValidation')]
        [string] $Issuer,

        # Accepted audiences (any-match).
        [Parameter(ParameterSetName = 'SignedValidation')]
        [Parameter(ParameterSetName = 'UnsignedValidation')]
        [string[]] $Audience,

        # Allowed clock skew for exp / nbf / iat checks.
        [Parameter(ParameterSetName = 'SignedValidation')]
        [Parameter(ParameterSetName = 'UnsignedValidation')]
        [timespan] $ClockSkew = [timespan]::Zero,

        # Require an exp claim. Defaults to $true.
        [Parameter(ParameterSetName = 'SignedValidation')]
        [Parameter(ParameterSetName = 'UnsignedValidation')]
        [bool] $RequireExpiration = $true,

        # Allow alg=none unsigned tokens.
        [Parameter(Mandatory, ParameterSetName = 'UnsignedValidation')]
        [switch] $AllowUnsigned,

        # Return a structured report instead of [bool].
        [Parameter(ParameterSetName = 'SignedValidation')]
        [Parameter(ParameterSetName = 'UnsignedValidation')]
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

        $supportedAlgs = @(
            'HS256', 'HS384', 'HS512',
            'RS256', 'RS384', 'RS512',
            'ES256', 'ES384', 'ES512',
            'PS256', 'PS384', 'PS512'
        )

        if ($PSCmdlet.ParameterSetName -eq 'UnsignedValidation') {
            if ($alg -ne 'none') {
                $algCheck.Passed = $false
                $algCheck.Reason = "Parameter set 'UnsignedValidation' only supports tokens with alg='none'."
                throw [System.Security.Authentication.AuthenticationException]::new($algCheck.Reason)
            }

            $sigCheck.Passed = $true
            $sigCheck.Reason = 'Skipped (unsigned token)'
            $signatureValidated = $false
        } else {
            if ($alg -eq 'none') {
                $algCheck.Passed = $false
                $algCheck.Reason = "Algorithm 'none' rejected. Use -AllowUnsigned for unsigned tokens."
                throw [System.Security.Authentication.AuthenticationException]::new($algCheck.Reason)
            }

            if ($alg -in $supportedAlgs) {
                $resolved = Resolve-JwtKey -Algorithm $alg -Key $Key
                try {
                    $sigOk = Test-JwtSignature `
                        -SigningInput $parsed.SigningInput() `
                        -Signature $parsed.Signature `
                        -Algorithm $alg `
                        -ResolvedKey $resolved
                } finally {
                    $shouldDispose = (
                        $resolved -is [System.IDisposable] -and
                        $Key -isnot [System.Security.Cryptography.RSA] -and
                        $Key -isnot [System.Security.Cryptography.ECDsa]
                    )
                    if ($shouldDispose) {
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
                $allowed = ($supportedAlgs + 'none') -join ', '
                $algCheck.Reason = "Algorithm '$alg' is not supported. Allowed: $allowed."
                throw [System.Security.Authentication.AuthenticationException]::new(
                    $algCheck.Reason)
            }
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

