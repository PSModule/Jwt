function New-Jwt {
    <#
        .SYNOPSIS
        Creates and signs a JSON Web Token (JWT).

        .DESCRIPTION
        Builds a JWT from a payload (and optional header overrides) and signs it using either a
        local RSA private key or an Azure Key Vault key. Returns a strongly typed [Jwt] object;
        call its ToString() method for the compact `header.payload.signature` form.

        Only RS256 is supported in this release.

        .EXAMPLE
        ```powershell
        New-Jwt -Payload @{ iss = 'app'; iat = 1700000000; exp = 1700003600 } -PrivateKey (Get-Content key.pem -Raw)
        ```

        Creates and signs a JWT with the given claims using a local RSA private key.

        .EXAMPLE
        ```powershell
        New-Jwt -Payload @{ iss = 'app'; iat = 1700000000; exp = 1700003600 } `
            -KeyVaultKeyReference 'https://myvault.vault.azure.net/keys/mykey'
        ```

        Creates and signs a JWT using an Azure Key Vault key. Requires Azure CLI or Az PowerShell
        to be installed and authenticated.

        .OUTPUTS
        Jwt
    #>
    [CmdletBinding(DefaultParameterSetName = 'LocalKey', SupportsShouldProcess)]
    [OutputType([Jwt])]
    param(
        # Optional header overrides. `alg` and `typ` are set automatically; pass `kid` or any
        # other JOSE header parameter here.
        [Parameter()]
        [hashtable] $Header,

        # The JWT payload / claims. Common registered claims (`iss`, `sub`, `aud`, `exp`, `nbf`,
        # `iat`, `jti`) are recognized; everything else flows through as private claims.
        [Parameter(Mandatory)]
        [hashtable] $Payload,

        # The RSA private key in PEM format. Accepts a [string] or a [securestring].
        [Parameter(Mandatory, ParameterSetName = 'LocalKey')]
        [object] $PrivateKey,

        # The Azure Key Vault key URL used for signing
        # (e.g. https://myvault.vault.azure.net/keys/mykey).
        [Parameter(Mandatory, ParameterSetName = 'KeyVault')]
        [string] $KeyVaultKeyReference,

        # The signing algorithm. RS256 is the only supported value in this release.
        [Parameter()]
        [ValidateSet('RS256')]
        [string] $Algorithm = 'RS256'
    )

    process {
        $headerData = @{ alg = $Algorithm; typ = 'JWT' }
        if ($Header) {
            foreach ($key in $Header.Keys) {
                $headerData[$key] = $Header[$key]
            }
        }

        if (-not $PSCmdlet.ShouldProcess('JWT', 'Create and sign')) { return }

        $unsigned = New-JwtUnsigned -Header $headerData -Payload $Payload

        switch ($PSCmdlet.ParameterSetName) {
            'LocalKey' { return Add-JwtLocalSignature -Jwt $unsigned -PrivateKey $PrivateKey }
            'KeyVault' { return Add-JwtKeyVaultSignature -Jwt $unsigned -KeyVaultKeyReference $KeyVaultKeyReference }
        }
    }
}
