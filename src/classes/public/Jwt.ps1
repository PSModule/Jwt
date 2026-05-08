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
        if ($value -is [JwtHeader] -or $value -is [JwtPayload]) {
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
