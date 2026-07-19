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

        .EXAMPLE
        Test-Jwt -Token $jwt -Key $secret -AllowedCriticalHeader 'kid'

        Validates a token that declares a supported critical JOSE header parameter.
        .LINK
        https://psmodule.io/Jwt/Functions/Token/Test-Jwt/

        .INPUTS
        System.Object

        .OUTPUTS
        System.Boolean
        System.Management.Automation.PSCustomObject

        .NOTES
        Tokens declaring a JOSE 'crit' header are rejected unless each declared critical
        parameter is explicitly allowed via -AllowedCriticalHeader.
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
        [switch] $Detailed,

        # Allow-list for JOSE critical header parameters declared in the token's 'crit' array.
        [Parameter(ParameterSetName = 'SignedValidation')]
        [Parameter(ParameterSetName = 'UnsignedValidation')]
        [string[]] $AllowedCriticalHeader
    )

    process {
        $parsed = ConvertFrom-Jwt -Token $Token
        $alg = $parsed.Header.alg

        $algCheck = @{ Name = 'Algorithm'; Passed = $true; Reason = $null }
        $criticalCheck = @{ Name = 'CriticalHeaders'; Passed = $true; Reason = $null }
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

                $headerValues = $parsed.Header.ToOrderedDictionary()
                if ($headerValues.Contains('crit')) {
                    $critRaw = $headerValues['crit']
                    if ($critRaw -is [string]) {
                        $critHeaders = @($critRaw)
                    } elseif ($critRaw -is [System.Collections.IEnumerable]) {
                        $critHeaders = @($critRaw)
                    } else {
                        $criticalCheck.Passed = $false
                        $criticalCheck.Reason = "JWT header 'crit' must be an array of strings. Got [$($critRaw.GetType().FullName)]."
                        throw [System.Security.Authentication.AuthenticationException]::new($criticalCheck.Reason)
                    }

                    $headerNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                    foreach ($name in $headerValues.Keys) {
                        [void]$headerNameSet.Add([string]$name)
                    }

                    $allowedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                    if ($PSBoundParameters.ContainsKey('AllowedCriticalHeader')) {
                        foreach ($name in $AllowedCriticalHeader) {
                            if (-not [string]::IsNullOrWhiteSpace($name)) {
                                [void]$allowedSet.Add($name)
                            }
                        }
                    }

                    $invalidNames = [System.Collections.Generic.List[string]]::new()
                    $missingHeaders = [System.Collections.Generic.List[string]]::new()
                    $unsupportedHeaders = [System.Collections.Generic.List[string]]::new()
                    foreach ($critName in $critHeaders) {
                        if ($critName -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$critName)) {
                            $invalidNames.Add([string]$critName)
                            continue
                        }

                        $name = [string]$critName
                        if (-not $headerNameSet.Contains($name)) {
                            $missingHeaders.Add($name)
                        }
                        if (-not $allowedSet.Contains($name)) {
                            $unsupportedHeaders.Add($name)
                        }
                    }

                    if ($invalidNames.Count -gt 0) {
                        $criticalCheck.Passed = $false
                        $criticalCheck.Reason = "JWT header 'crit' contains non-string or empty values."
                        throw [System.Security.Authentication.AuthenticationException]::new($criticalCheck.Reason)
                    }
                    if ($missingHeaders.Count -gt 0) {
                        $missing = $missingHeaders -join ', '
                        $criticalCheck.Passed = $false
                        $criticalCheck.Reason = "JWT header 'crit' references parameters not present in header: $missing."
                        throw [System.Security.Authentication.AuthenticationException]::new($criticalCheck.Reason)
                    }
                    if ($unsupportedHeaders.Count -gt 0) {
                        $unsupported = $unsupportedHeaders -join ', '
                        $criticalCheck.Passed = $false
                        $criticalCheck.Reason = "Unsupported critical header parameters: $unsupported. Supply -AllowedCriticalHeader to explicitly permit them."
                        throw [System.Security.Authentication.AuthenticationException]::new($criticalCheck.Reason)
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

        $checks = @($algCheck, $criticalCheck, $sigCheck) + $claimChecks
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
