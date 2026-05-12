class JwtBase64Url {
    static [string] Encode([byte[]] $bytes) {
        if ($null -eq $bytes -or $bytes.Length -eq 0) { return '' }
        $b64 = [Convert]::ToBase64String($bytes)
        return $b64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    static [string] EncodeString([string] $value) {
        if ($null -eq $value) { return '' }
        return [JwtBase64Url]::Encode([System.Text.Encoding]::UTF8.GetBytes($value))
    }

    static [byte[]] Decode([string] $value) {
        if ([string]::IsNullOrEmpty($value)) { return , [byte[]]::new(0) }
        $s = $value.Replace('-', '+').Replace('_', '/')
        switch ($s.Length % 4) {
            2 { $s += '==' }
            3 { $s += '=' }
            0 {}
            default { throw [System.FormatException]::new("Invalid base64url string length: $($value.Length).") }
        }
        return [Convert]::FromBase64String($s)
    }

    static [string] DecodeString([string] $value) {
        return [System.Text.Encoding]::UTF8.GetString([JwtBase64Url]::Decode($value))
    }
}
