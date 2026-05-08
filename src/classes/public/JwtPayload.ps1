class JwtPayload {
    [string] $iss
    [string] $sub
    [object] $aud
    [Nullable[long]] $exp
    [Nullable[long]] $nbf
    [Nullable[long]] $iat
    [string] $jti
    [hashtable] $AdditionalFields = @{}

    JwtPayload() {}

    JwtPayload([System.Collections.IDictionary] $Data) {
        foreach ($key in $Data.Keys) {
            switch ($key) {
                'iss' { $this.iss = [string]$Data[$key] }
                'sub' { $this.sub = [string]$Data[$key] }
                'aud' { $this.aud = $Data[$key] }
                'exp' { $this.exp = [long]$Data[$key] }
                'nbf' { $this.nbf = [long]$Data[$key] }
                'iat' { $this.iat = [long]$Data[$key] }
                'jti' { $this.jti = [string]$Data[$key] }
                default { $this.AdditionalFields[$key] = $Data[$key] }
            }
        }
    }

    [System.Collections.Specialized.OrderedDictionary] ToOrderedDictionary() {
        $h = [ordered]@{}
        if ($this.iss) { $h['iss'] = $this.iss }
        if ($this.sub) { $h['sub'] = $this.sub }
        if ($null -ne $this.aud) { $h['aud'] = $this.aud }
        if ($this.exp.HasValue) { $h['exp'] = $this.exp.Value }
        if ($this.nbf.HasValue) { $h['nbf'] = $this.nbf.Value }
        if ($this.iat.HasValue) { $h['iat'] = $this.iat.Value }
        if ($this.jti) { $h['jti'] = $this.jti }
        foreach ($key in $this.AdditionalFields.Keys) {
            if (-not $h.Contains($key)) { $h[$key] = $this.AdditionalFields[$key] }
        }
        return $h
    }
}
