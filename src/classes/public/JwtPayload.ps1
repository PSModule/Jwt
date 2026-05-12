class JwtPayload {
    [string] $iss
    [string] $sub
    [object] $aud
    [Nullable[long]] $exp
    [Nullable[long]] $nbf
    [Nullable[long]] $iat
    [string] $jti
    [System.Collections.Specialized.OrderedDictionary] $AdditionalFields = [ordered]@{}
    hidden [System.Collections.Generic.List[string]] $_keyOrder = [System.Collections.Generic.List[string]]::new()

    static [string[]] $RegisteredClaims = @('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti')

    JwtPayload() {}

    JwtPayload([System.Collections.IDictionary] $values) {
        if ($null -eq $values) { return }
        foreach ($key in $values.Keys) {
            $this._keyOrder.Add([string]$key)
            switch ([string]$key) {
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

    hidden [object] _GetValueFor([string] $key) {
        switch ($key) {
            'iss' { if ($this.iss) { return $this.iss } else { return [System.Management.Automation.Internal.AutomationNull]::Value } }
            'sub' { if ($this.sub) { return $this.sub } else { return [System.Management.Automation.Internal.AutomationNull]::Value } }
            'aud' { if ($null -ne $this.aud) { return $this.aud } else { return [System.Management.Automation.Internal.AutomationNull]::Value } }
            'exp' { if ($null -ne $this.exp) { return [long]$this.exp } else { return [System.Management.Automation.Internal.AutomationNull]::Value } }
            'nbf' { if ($null -ne $this.nbf) { return [long]$this.nbf } else { return [System.Management.Automation.Internal.AutomationNull]::Value } }
            'iat' { if ($null -ne $this.iat) { return [long]$this.iat } else { return [System.Management.Automation.Internal.AutomationNull]::Value } }
            'jti' { if ($this.jti) { return $this.jti } else { return [System.Management.Automation.Internal.AutomationNull]::Value } }
            default {
                if ($this.AdditionalFields.Contains($key)) { return $this.AdditionalFields[$key] }
                return [System.Management.Automation.Internal.AutomationNull]::Value
            }
        }
        return [System.Management.Automation.Internal.AutomationNull]::Value
    }

    [System.Collections.Specialized.OrderedDictionary] ToOrderedDictionary() {
        $o = [ordered]@{}
        $emitted = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($key in $this._keyOrder) {
            $val = $this._GetValueFor($key)
            if ($null -ne $val -and $val -isnot [System.Management.Automation.Internal.AutomationNull]) {
                $o[$key] = $val
                [void]$emitted.Add($key)
            }
        }
        foreach ($claim in [JwtPayload]::RegisteredClaims) {
            if ($emitted.Contains($claim)) { continue }
            $val = $this._GetValueFor($claim)
            if ($null -ne $val -and $val -isnot [System.Management.Automation.Internal.AutomationNull]) {
                $o[$claim] = $val
                [void]$emitted.Add($claim)
            }
        }
        foreach ($key in $this.AdditionalFields.Keys) {
            if ($emitted.Contains($key)) { continue }
            $o[$key] = $this.AdditionalFields[$key]
            [void]$emitted.Add($key)
        }
        return $o
    }

    [string] ToJson() {
        return ConvertTo-Json -InputObject $this.ToOrderedDictionary() -Depth 100 -Compress
    }
}
