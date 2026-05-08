class JwtHeader {
    [string] $alg
    [string] $typ = 'JWT'
    [string] $kid
    [hashtable] $AdditionalFields = @{}

    JwtHeader() {}

    JwtHeader([System.Collections.IDictionary] $Data) {
        foreach ($key in $Data.Keys) {
            switch ($key) {
                'alg' { $this.alg = [string]$Data[$key] }
                'typ' { $this.typ = [string]$Data[$key] }
                'kid' { $this.kid = [string]$Data[$key] }
                default { $this.AdditionalFields[$key] = $Data[$key] }
            }
        }
    }

    [System.Collections.Specialized.OrderedDictionary] ToOrderedDictionary() {
        $h = [ordered]@{}
        if ($this.alg) { $h['alg'] = $this.alg }
        if ($this.typ) { $h['typ'] = $this.typ }
        if ($this.kid) { $h['kid'] = $this.kid }
        foreach ($key in $this.AdditionalFields.Keys) {
            if (-not $h.Contains($key)) { $h[$key] = $this.AdditionalFields[$key] }
        }
        return $h
    }
}
