class Jwt {
    # Property types are intentionally [object] so this class file can be parsed before its
    # sibling class files (JwtHeader, JwtPayload) are loaded. Constructor parameters still
    # enforce the concrete types.
    [object] $Header
    [object] $Payload
    [string] $Signature
    [string] $EncodedHeader
    [string] $EncodedPayload

    Jwt() {}

    Jwt([JwtHeader] $Header, [JwtPayload] $Payload) {
        $this.Header = $Header
        $this.Payload = $Payload
        $this.EncodedHeader = [JwtBase64Url]::Encode($Header.ToOrderedDictionary())
        $this.EncodedPayload = [JwtBase64Url]::Encode($Payload.ToOrderedDictionary())
        $this.Signature = ''
    }

    Jwt([JwtHeader] $Header, [JwtPayload] $Payload, [string] $Signature) {
        $this.Header = $Header
        $this.Payload = $Payload
        $this.EncodedHeader = [JwtBase64Url]::Encode($Header.ToOrderedDictionary())
        $this.EncodedPayload = [JwtBase64Url]::Encode($Payload.ToOrderedDictionary())
        $this.Signature = $Signature
    }

    [string] SigningInput() {
        return "$($this.EncodedHeader).$($this.EncodedPayload)"
    }

    [string] ToString() {
        return "$($this.EncodedHeader).$($this.EncodedPayload).$($this.Signature)"
    }
}
