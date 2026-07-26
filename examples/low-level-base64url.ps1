$json = '{"sub":"joe"}'
$encoded = [JwtBase64Url]::EncodeString($json)
$decoded = [JwtBase64Url]::DecodeString($encoded)

$encoded
$decoded
