class Jwt {
    [JwtHeader] $Header
    [JwtPayload] $Payload
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
