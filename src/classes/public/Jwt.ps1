class Jwt {
    [JwtHeader] $Header
    [JwtPayload] $Payload
    [string] $Signature
    [string] $EncodedHeader
    [string] $EncodedPayload

    Jwt() {}

    Jwt([JwtHeader] $header, [JwtPayload] $payload) {
        $this.Header = $header
        $this.Payload = $payload
        $this.EncodedHeader = [JwtBase64Url]::EncodeString($header.ToJson())
        $this.EncodedPayload = [JwtBase64Url]::EncodeString($payload.ToJson())
        $this.Signature = ''
    }

    Jwt([JwtHeader] $header, [JwtPayload] $payload, [string] $signature) {
        $this.Header = $header
        $this.Payload = $payload
        $this.EncodedHeader = [JwtBase64Url]::EncodeString($header.ToJson())
        $this.EncodedPayload = [JwtBase64Url]::EncodeString($payload.ToJson())
        $this.Signature = $signature
    }

    Jwt(
        [JwtHeader] $header,
        [JwtPayload] $payload,
        [string] $signature,
        [string] $encodedHeader,
        [string] $encodedPayload
    ) {
        $this.Header = $header
        $this.Payload = $payload
        $this.EncodedHeader = $encodedHeader
        $this.EncodedPayload = $encodedPayload
        $this.Signature = $signature
    }

    [string] SigningInput() {
        return "$($this.EncodedHeader).$($this.EncodedPayload)"
    }

    [string] ToString() {
        return "$($this.EncodedHeader).$($this.EncodedPayload).$($this.Signature)"
    }
}
