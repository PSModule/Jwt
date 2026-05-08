class JwtBase64Url {
    static [string] Encode([byte[]] $Bytes) {
        return [JwtBase64Url]::ConvertToBase64UrlFormat([System.Convert]::ToBase64String($Bytes))
    }

    static [string] Encode([string] $String) {
        return [JwtBase64Url]::Encode([System.Text.Encoding]::UTF8.GetBytes($String))
    }

    static [string] Encode([System.Collections.IDictionary] $Data) {
        return [JwtBase64Url]::Encode((ConvertTo-Json -InputObject $Data -Compress -Depth 100))
    }

    static [string] ConvertToBase64UrlFormat([string] $Base64String) {
        return $Base64String.TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
}
