class JwtHeader {
    <#
        .SYNOPSIS
        Typed JOSE header for a JWT.

        .DESCRIPTION
        Represents the JOSE header object of a JWT (RFC 7515 §4). Holds the registered
        header parameters used by this module (`alg`, `typ`, `kid`) plus an `AdditionalFields`
        hashtable for any other JOSE parameters that should round-trip.
    #>

    [string] $alg
    [string] $typ = 'JWT'
    [string] $kid
    [hashtable] $AdditionalFields = @{}

    JwtHeader() {}

    JwtHeader([hashtable] $values) {
        if ($null -eq $values) { return }
        foreach ($key in $values.Keys) {
            switch ($key) {
                'alg' { $this.alg = [string]$values[$key] }
                'typ' { $this.typ = [string]$values[$key] }
                'kid' { $this.kid = [string]$values[$key] }
                default { $this.AdditionalFields[$key] = $values[$key] }
            }
        }
    }

    [System.Collections.Specialized.OrderedDictionary] ToOrderedDictionary() {
        $ordered = [ordered]@{}
        if (-not [string]::IsNullOrEmpty($this.alg)) { $ordered['alg'] = $this.alg }
        if (-not [string]::IsNullOrEmpty($this.typ)) { $ordered['typ'] = $this.typ }
        if (-not [string]::IsNullOrEmpty($this.kid)) { $ordered['kid'] = $this.kid }
        if ($null -ne $this.AdditionalFields) {
            foreach ($key in $this.AdditionalFields.Keys) {
                if ($ordered.Contains($key)) { continue }
                $ordered[$key] = $this.AdditionalFields[$key]
            }
        }
        return $ordered
    }
}
