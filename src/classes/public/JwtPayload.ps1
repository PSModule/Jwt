class JwtPayload {
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
        $o = [ordered]@{}
        if ($this.iss) { $o['iss'] = $this.iss }
        if ($this.sub) { $o['sub'] = $this.sub }
        if ($null -ne $this.aud) { $o['aud'] = $this.aud }
        if ($this.exp.HasValue) { $o['exp'] = $this.exp.Value }
        if ($this.nbf.HasValue) { $o['nbf'] = $this.nbf.Value }
        if ($this.iat.HasValue) { $o['iat'] = $this.iat.Value }
        if ($this.jti) { $o['jti'] = $this.jti }
        if ($null -ne $this.AdditionalFields) {
            foreach ($key in $this.AdditionalFields.Keys) {
                $o[$key] = $this.AdditionalFields[$key]
            }
        }
        return $o
    }

    [string] ToJson() {
        return ConvertTo-Json -InputObject $this.ToOrderedDictionary() -Depth 100 -Compress
    }
}
