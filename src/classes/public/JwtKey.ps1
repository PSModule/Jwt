class JwtKey {
    <#
        .SYNOPSIS
        JSON Web Key (JWK) representation per RFC 7517.

        .DESCRIPTION
        Strongly-typed container for a JWK. All key-material fields are Base64URL strings
        (RFC 7518 §2). `AdditionalFields` is provided for forward compatibility with future
        JWK extensions.
    #>

    [string] $kty
    [string] $use
    [string[]] $key_ops
    [string] $alg
    [string] $kid
    [string] $x5u
    [string[]] $x5c
    [string] $x5t
    [string] ${x5t#S256}

    [string] $n
    [string] $e
    [string] $d
    [string] $p
    [string] $q
    [string] $dp
    [string] $dq
    [string] $qi
    [object[]] $oth

    [string] $crv
    [string] $x
    [string] $y

    [string] $k

    [hashtable] $AdditionalFields = @{}

    static [string[]] $KnownFields = @(
        'kty', 'use', 'key_ops', 'alg', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256',
        'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth',
        'crv', 'x', 'y',
        'k'
    )

    JwtKey() {}

    JwtKey([hashtable] $values) {
        if ($null -eq $values) { return }
        foreach ($key in $values.Keys) {
            if ([JwtKey]::KnownFields -contains $key) {
                $this.$key = $values[$key]
            } else {
                $this.AdditionalFields[$key] = $values[$key]
            }
        }
    }

    [System.Collections.Specialized.OrderedDictionary] ToOrderedDictionary() {
        $ordered = [ordered]@{}
        foreach ($field in [JwtKey]::KnownFields) {
            $value = $this.$field
            if ($null -eq $value) { continue }
            if ($value -is [string] -and [string]::IsNullOrEmpty($value)) { continue }
            if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                $hasAny = $false
                foreach ($item in $value) { $hasAny = $true; break }
                if (-not $hasAny) { continue }
            }
            $ordered[$field] = $value
        }
        if ($null -ne $this.AdditionalFields) {
            foreach ($key in $this.AdditionalFields.Keys) {
                if ($ordered.Contains($key)) { continue }
                $ordered[$key] = $this.AdditionalFields[$key]
            }
        }
        return $ordered
    }
}
