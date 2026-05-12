class JwtKeySet {
    [JwtKey[]] $keys = @()
    [System.Collections.Specialized.OrderedDictionary] $AdditionalFields = [ordered]@{}

    JwtKeySet() {}

    JwtKeySet([JwtKey[]] $keys) {
        if ($null -ne $keys) { $this.keys = $keys }
    }

    JwtKeySet([System.Collections.IDictionary] $values) {
        if ($null -eq $values) { return }
        foreach ($key in $values.Keys) {
            if ($key -eq 'keys') {
                $list = [System.Collections.Generic.List[JwtKey]]::new()
                foreach ($entry in $values[$key]) {
                    if ($entry -is [JwtKey]) { $list.Add($entry); continue }
                    if ($entry -is [System.Collections.IDictionary]) {
                        $list.Add([JwtKey]::new([hashtable]$entry))
                        continue
                    }
                    throw [System.ArgumentException]::new(
                        "JWK Set 'keys' entries must be JwtKey or IDictionary. Got [$($entry.GetType().FullName)]."
                    )
                }
                $this.keys = $list.ToArray()
            } else {
                $this.AdditionalFields[$key] = $values[$key]
            }
        }
    }

    [JwtKey] FindByKid([string] $kid) {
        foreach ($key in $this.keys) {
            if ($key.kid -eq $kid) { return $key }
        }
        return $null
    }

    [System.Collections.Specialized.OrderedDictionary] ToOrderedDictionary() {
        $o = [ordered]@{}
        $keyDicts = [System.Collections.Generic.List[System.Collections.Specialized.OrderedDictionary]]::new()
        foreach ($key in $this.keys) {
            $keyDicts.Add($key.ToOrderedDictionary())
        }
        $o['keys'] = $keyDicts.ToArray()
        foreach ($field in $this.AdditionalFields.Keys) {
            $o[$field] = $this.AdditionalFields[$field]
        }
        return $o
    }

    [string] ToJson() {
        return ConvertTo-Json -InputObject $this.ToOrderedDictionary() -Depth 100 -Compress
    }
}
