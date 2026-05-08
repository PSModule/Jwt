class JwtBase64Url {
    <#
        .SYNOPSIS
        Base64URL encoding and decoding helpers.

        .DESCRIPTION
        Provides Base64URL (RFC 4648 §5) encoding and decoding for the JOSE/JWT family of specs.
        Internal class; not part of the public surface.
    #>

    static [string] Encode([byte[]] $bytes) {
        if ($null -eq $bytes) { return [string]::Empty }
        $b64 = [Convert]::ToBase64String($bytes)
        return $b64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    static [string] EncodeString([string] $text) {
        if ($null -eq $text) { return [string]::Empty }
        return [JwtBase64Url]::Encode([System.Text.Encoding]::UTF8.GetBytes($text))
    }

    static [byte[]] Decode([string] $value) {
        if ([string]::IsNullOrEmpty($value)) { return [byte[]]::new(0) }
        $b64 = $value.Replace('-', '+').Replace('_', '/')
        switch ($b64.Length % 4) {
            2 { $b64 += '==' }
            3 { $b64 += '=' }
            1 { throw "Invalid Base64URL string: length $($value.Length) is not valid." }
        }
        return [Convert]::FromBase64String($b64)
    }

    static [string] DecodeString([string] $value) {
        return [System.Text.Encoding]::UTF8.GetString([JwtBase64Url]::Decode($value))
    }
}
