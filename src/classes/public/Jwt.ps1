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

class Jwt {
    <#
        .SYNOPSIS
        A parsed or constructed JSON Web Token.

        .DESCRIPTION
        Holds the typed `Header` and `Payload`, the encoded segments (`EncodedHeader`,
        `EncodedPayload`), and the `Signature`. The encoded segments are computed once
        at construction time from the supplied header/payload and are not recomputed when
        the underlying objects mutate. To rebuild from a mutated header/payload, construct
        a new `[Jwt]`.

        `SigningInput()` returns the live "$EncodedHeader.$EncodedPayload" string used by
        signers and verifiers. `ToString()` returns the compact JWT form
        ("$EncodedHeader.$EncodedPayload.$Signature"); for an unsigned token this yields a
        trailing dot.
    #>

    [object] $Header
    [object] $Payload
    [string] $Signature
    [string] $EncodedHeader
    [string] $EncodedPayload

    Jwt() {}

    Jwt([object] $header, [object] $payload) {
        $this.Header = $header
        $this.Payload = $payload
        $this.EncodedHeader = [Jwt]::EncodeSegment($header)
        $this.EncodedPayload = [Jwt]::EncodeSegment($payload)
        $this.Signature = ''
    }

    Jwt([object] $header, [object] $payload, [string] $signature) {
        $this.Header = $header
        $this.Payload = $payload
        $this.EncodedHeader = [Jwt]::EncodeSegment($header)
        $this.EncodedPayload = [Jwt]::EncodeSegment($payload)
        $this.Signature = $signature
    }

    static hidden [string] EncodeSegment([object] $value) {
        if ($null -eq $value) { return '' }
        $dict = $null
        if ($null -ne $value.PSObject.Methods['ToOrderedDictionary']) {
            $dict = $value.ToOrderedDictionary()
        } else {
            $dict = $value
        }
        $json = ConvertTo-Json -InputObject $dict -Depth 100 -Compress
        return [JwtBase64Url]::EncodeString($json)
    }

    [string] SigningInput() {
        return "$($this.EncodedHeader).$($this.EncodedPayload)"
    }

    [string] ToString() {
        return "$($this.EncodedHeader).$($this.EncodedPayload).$($this.Signature)"
    }
}
