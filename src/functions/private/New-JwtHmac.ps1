function New-JwtHmac {
    <#
        .SYNOPSIS
        Creates an [HMAC] instance sized for an HS-family JWS algorithm.

        .DESCRIPTION
        Internal factory that maps HS256/HS384/HS512 to HMACSHA256/384/512. Centralized
        so Resolve-JwtKey, Test-JwtSignature, and New-Jwt all agree on the hash size.
    #>
    [OutputType([System.Security.Cryptography.HMAC])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('HS256', 'HS384', 'HS512')]
        [string] $Algorithm,

        [Parameter(Mandatory)]
        [byte[]] $KeyBytes
    )

    switch ($Algorithm) {
        'HS256' { return [System.Security.Cryptography.HMACSHA256]::new($KeyBytes) }
        'HS384' { return [System.Security.Cryptography.HMACSHA384]::new($KeyBytes) }
        'HS512' { return [System.Security.Cryptography.HMACSHA512]::new($KeyBytes) }
    }
    return $null
}
