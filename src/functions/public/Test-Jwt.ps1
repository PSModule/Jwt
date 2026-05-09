function Test-Jwt {
    <#
        .SYNOPSIS
        Verify the signature and validate the registered claims of a JWT.

        .DESCRIPTION
        Performs algorithm-key compatibility validation, signature verification, and the
        registered-claim checks (`exp`, `nbf`, `iss`, `aud`) defined by RFC 7519 §4.1.

        Algorithm-key compatibility is checked first, before any signature work, to block
        algorithm-confusion attacks (e.g., a token with header `alg=HS256` presented to a
        verifier holding an RSA public key). Mismatches throw a terminating error.

        Supported algorithms: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512,
        ES256, ES384, ES512, none.

        Returns `$true`/`$false` by default. With `-Detailed`, returns a structured
        `[pscustomobject]` describing the per-check outcome.

        .EXAMPLE
        ```powershell
        $tokenString | Test-Jwt -Key $publicPem -Issuer 'myapp' -Audience 'api://myapi'
        ```

        Returns `$true` if signature and claims validate.

        .EXAMPLE
        ```powershell
        Test-Jwt -Token $tokenString -Key $publicPem -Detailed
        ```

        Returns a structured result describing every check.

        .OUTPUTS
        System.Boolean or System.Management.Automation.PSCustomObject
    #>
    [OutputType([bool], [pscustomobject])]
    [CmdletBinding(DefaultParameterSetName = 'Signed')]
    param(
        # The JWT to validate.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object] $Token,

        # Verification key. Type must match the algorithm in the token header.
        [Parameter(Mandatory, ParameterSetName = 'Signed')]
        [object] $Key,

        # Allow tokens with `alg=none` (unsigned). Signature verification is skipped; claim
        # validation still runs.
        [Parameter(Mandatory, ParameterSetName = 'Unsigned')]
        [switch] $AllowUnsigned,

        # Expected issuer (`iss` claim).
        [Parameter()]
        [string] $Issuer,

        # Expected audience(s). Validation passes if at least one matches the token `aud`.
        [Parameter()]
        [string[]] $Audience,

        # Permitted clock drift for `exp`/`nbf`.
        [Parameter()]
        [timespan] $ClockSkew = ([timespan]::Zero),

        # Require an `exp` claim. Defaults to `$true`.
        [Parameter()]
        [bool] $RequireExpiration = $true,

        # Return a structured per-check result instead of a boolean.
        [Parameter()]
        [switch] $Detailed
    )

    process {
        $jwt = if ($Token -is [Jwt]) { $Token } else { ConvertFrom-Jwt -Token $Token }
        $alg = $jwt.Header.alg

        $supported = @(
            'HS256', 'HS384', 'HS512',
            'RS256', 'RS384', 'RS512',
            'PS256', 'PS384', 'PS512',
            'ES256', 'ES384', 'ES512',
            'none'
        )

        if ([string]::IsNullOrEmpty($alg)) {
            throw "JWT header is missing the 'alg' claim."
        }
        if ($supported -notcontains $alg) {
            throw "Unsupported or unrecognized algorithm '$alg'."
        }

        $sigCheck = $null
        $signatureValidated = $false

        if ($alg -eq 'none') {
            if (-not $AllowUnsigned) {
                throw "Token uses 'alg=none'; pass -AllowUnsigned to accept unsigned tokens."
            }
            if ($PSBoundParameters.ContainsKey('Key') -and $null -ne $Key) {
                throw "alg=none does not accept a key; do not pass -Key with -AllowUnsigned."
            }
            $sigCheck = @{ Name = 'Signature'; Passed = $false; Reason = 'Skipped (unsigned token)' }
        } else {
            if ($AllowUnsigned -and $alg -ne 'none') {
                throw "-AllowUnsigned is only valid for tokens with alg=none; this token uses '$alg'."
            }
            $signatureValidated = Test-JwtSignature -Jwt $jwt -Key $Key
            $sigCheck = if ($signatureValidated) {
                @{ Name = 'Signature'; Passed = $true; Reason = $null }
            } else {
                @{ Name = 'Signature'; Passed = $false; Reason = 'Signature does not verify against the supplied key.' }
            }
        }

        $algCheck = @{ Name = 'Algorithm'; Passed = $true; Reason = $null }

        $claimParams = @{
            Payload           = $jwt.Payload
            ClockSkew         = $ClockSkew
            RequireExpiration = $RequireExpiration
        }
        if ($PSBoundParameters.ContainsKey('Issuer')) { $claimParams['Issuer'] = $Issuer }
        if ($PSBoundParameters.ContainsKey('Audience')) { $claimParams['Audience'] = $Audience }
        $claimChecks = Test-JwtClaim @claimParams

        $allChecks = @($algCheck, $sigCheck) + $claimChecks
        $valid = ($allChecks | Where-Object { -not $_.Passed }).Count -eq 0

        if ($Detailed) {
            return [pscustomobject]@{
                Valid              = $valid
                SignatureValidated = $signatureValidated
                Algorithm          = $alg
                Checks             = $allChecks
            }
        }
        return $valid
    }
}
