function Get-JwtKeyFromSet {
    <#
        .SYNOPSIS
        Looks up a [JwtKey] in a [JwtKeySet] by kid.

        .DESCRIPTION
        Returns the first [JwtKey] in the set whose kid matches. Returns $null when no
        match is found. Pass -ErrorIfMissing to escalate to a non-terminating error.

        .EXAMPLE
        $key = Get-JwtKeyFromSet -KeySet $jwks -KeyId (Get-JwtHeader $token).kid

        Resolves the signing key for a token by reading the header kid and looking it
        up in a JWKS.

        .OUTPUTS
        JwtKey
    #>
    [OutputType([JwtKey])]
    [CmdletBinding()]
    param(
        # The JWK Set to search.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [JwtKeySet] $KeySet,

        # The kid to find.
        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $KeyId,

        # Emit a non-terminating error when the kid is not found.
        [Parameter()]
        [switch] $ErrorIfMissing
    )

    process {
        $match = $KeySet.FindByKid($KeyId)
        if ($null -eq $match -and $ErrorIfMissing) {
            Write-Error "No JWK in the set has kid='$KeyId'."
        }
        return $match
    }
}
