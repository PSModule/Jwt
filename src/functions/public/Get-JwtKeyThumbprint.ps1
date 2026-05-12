function Get-JwtKeyThumbprint {
    <#
        .SYNOPSIS
        Computes the JWK Thumbprint of a key per RFC 7638.

        .DESCRIPTION
        Builds the canonical JSON representation containing only the required members
        for the key's kty (per RFC 7638 §3.2), in lexicographic order, with no
        whitespace; hashes it with the requested hash algorithm; and returns the
        base64url-encoded digest.

        Required members:
        - RSA: e, kty, n
        - EC : crv, kty, x, y
        - oct: k, kty

        .EXAMPLE
        Get-JwtKeyThumbprint -Key $jwk

        Returns the SHA-256 thumbprint as a base64url string suitable for use as a kid.

        .EXAMPLE
        Get-JwtKeyThumbprint -Key $jwk -HashAlgorithm SHA384

        Returns the SHA-384 thumbprint.

        .OUTPUTS
        System.String
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        # The JWK to fingerprint.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [JwtKey] $Key,

        # The hash algorithm. Default SHA-256 per RFC 7638 §3.4.
        [Parameter()]
        [ValidateSet('SHA256', 'SHA384', 'SHA512')]
        [string] $HashAlgorithm = 'SHA256'
    )

    process {
        $required = switch ($Key.kty) {
            'RSA' { @('e', 'kty', 'n') }
            'EC' { @('crv', 'kty', 'x', 'y') }
            'oct' { @('k', 'kty') }
            default {
                throw [System.NotSupportedException]::new(
                    "JWK kty '$($Key.kty)' is not supported by RFC 7638 thumbprint."
                )
            }
        }

        $canonical = [ordered]@{}
        foreach ($field in $required) {
            $value = $Key.$field
            if ([string]::IsNullOrEmpty($value)) {
                throw [System.InvalidOperationException]::new(
                    "JWK is missing required field '$field' for thumbprint computation."
                )
            }
            $canonical[$field] = $value
        }

        $json = ConvertTo-Json -InputObject $canonical -Depth 10 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

        $hasher = switch ($HashAlgorithm) {
            'SHA256' { [System.Security.Cryptography.SHA256]::Create() }
            'SHA384' { [System.Security.Cryptography.SHA384]::Create() }
            'SHA512' { [System.Security.Cryptography.SHA512]::Create() }
        }
        try {
            $digest = $hasher.ComputeHash($bytes)
        } finally {
            $hasher.Dispose()
        }
        return [JwtBase64Url]::Encode($digest)
    }
}
