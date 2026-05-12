function Get-JwtAlgorithmHash {
    <#
        .SYNOPSIS
        Returns the [HashAlgorithmName] used by a JWS algorithm.

        .DESCRIPTION
        Internal helper used by signing and verification to map RFC 7518 §3 algorithm
        names to the .NET HashAlgorithmName enum.
    #>
    [OutputType([System.Security.Cryptography.HashAlgorithmName])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Algorithm
    )

    switch -Regex ($Algorithm) {
        '256$' { return [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
        '384$' { return [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
        '512$' { return [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
    }
    throw [System.NotSupportedException]::new("No hash mapping for algorithm '$Algorithm'.")
}
