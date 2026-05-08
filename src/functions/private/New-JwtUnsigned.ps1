function New-JwtUnsigned {
    <#
        .SYNOPSIS
        Builds an unsigned JWT (header.payload) from a header and a payload.

        .DESCRIPTION
        Composes a [Jwt] object whose Signature property is empty. The encoded header and payload are
        ready to be signed by Add-JwtLocalSignature or Add-JwtKeyVaultSignature.

        .EXAMPLE
        ```powershell
        New-JwtUnsigned -Header @{ alg = 'RS256'; typ = 'JWT' } -Payload @{ iss = 'app'; iat = 1700000000; exp = 1700003600 }
        ```

        Returns a [Jwt] object with no signature.

        .OUTPUTS
        Jwt
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Function builds an in-memory object without modifying system state'
    )]
    [CmdletBinding()]
    [OutputType([Jwt])]
    param(
        # The JWT header (alg, typ, kid, plus any custom fields).
        [Parameter(Mandatory)]
        [hashtable] $Header,

        # The JWT payload / claims (iss, sub, aud, exp, nbf, iat, jti, plus any custom claims).
        [Parameter(Mandatory)]
        [hashtable] $Payload
    )

    process {
        $jwtHeader = [JwtHeader]::new($Header)
        $jwtPayload = [JwtPayload]::new($Payload)
        return [Jwt]::new($jwtHeader, $jwtPayload)
    }
}
