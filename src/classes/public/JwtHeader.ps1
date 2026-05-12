class JwtHeader {
    [string] $alg
    [string] $typ = 'JWT'
    [string] $kid
    [hashtable] $AdditionalFields = @{}

    JwtHeader() {}

    JwtHeader([System.Collections.IDictionary] $values) {
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
        $o = [ordered]@{}
        if ($this.alg) { $o['alg'] = $this.alg }
        if ($this.typ) { $o['typ'] = $this.typ }
        if ($this.kid) { $o['kid'] = $this.kid }
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
