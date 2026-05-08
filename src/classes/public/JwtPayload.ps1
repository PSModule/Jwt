class JwtPayload {
    <#
        .SYNOPSIS
        Typed JWT payload (claim set).

        .DESCRIPTION
        Represents the claim set of a JWT (RFC 7519 §4). Registered claims are exposed as
        named properties; everything else is preserved on `AdditionalFields` so it round-trips.
        The `aud` claim is typed `[object]` because RFC 7519 §4.1.3 allows either a single
        StringOrURI or an array of them.
    #>

    [string] $iss
    [string] $sub
    [object] $aud
    [Nullable[long]] $exp
    [Nullable[long]] $nbf
    [Nullable[long]] $iat
    [string] $jti
    [hashtable] $AdditionalFields = @{}

    static [string[]] $RegisteredClaims = @('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti')

    JwtPayload() {}

    JwtPayload([hashtable] $values) {
        if ($null -eq $values) { return }
        foreach ($key in $values.Keys) {
            switch ($key) {
                'iss' { $this.iss = [string]$values[$key] }
                'sub' { $this.sub = [string]$values[$key] }
                'aud' { $this.aud = $values[$key] }
                'exp' { $this.exp = [long]$values[$key] }
                'nbf' { $this.nbf = [long]$values[$key] }
                'iat' { $this.iat = [long]$values[$key] }
                'jti' { $this.jti = [string]$values[$key] }
                default { $this.AdditionalFields[$key] = $values[$key] }
            }
        }
    }

    [System.Collections.Specialized.OrderedDictionary] ToOrderedDictionary() {
        $ordered = [ordered]@{}
        if (-not [string]::IsNullOrEmpty($this.iss)) { $ordered['iss'] = $this.iss }
        if (-not [string]::IsNullOrEmpty($this.sub)) { $ordered['sub'] = $this.sub }
        if ($null -ne $this.aud) { $ordered['aud'] = $this.aud }
        if ($null -ne $this.exp) { $ordered['exp'] = [long]$this.exp }
        if ($null -ne $this.nbf) { $ordered['nbf'] = [long]$this.nbf }
        if ($null -ne $this.iat) { $ordered['iat'] = [long]$this.iat }
        if (-not [string]::IsNullOrEmpty($this.jti)) { $ordered['jti'] = $this.jti }
        if ($null -ne $this.AdditionalFields) {
            foreach ($key in $this.AdditionalFields.Keys) {
                if ($ordered.Contains($key)) { continue }
                $ordered[$key] = $this.AdditionalFields[$key]
            }
        }
        return $ordered
    }
}
