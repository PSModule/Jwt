$rsa = New-JwtSigningKey -Algorithm RS256
$ec = New-JwtSigningKey -Algorithm ES256

try {
    $rsaJwk = ConvertTo-JwtKey -Key $rsa -KeyId 'rsa-1' -Algorithm RS256
    $ecJwk = ConvertTo-JwtKey -Key $ec -KeyId 'ec-1' -Algorithm ES256
    $set = $rsaJwk, $ecJwk | ConvertTo-JwtKeySet

    # Path 1: keep explicit key ownership in caller code
    $token = New-Jwt -Payload @{ sub = 'app' } -Algorithm ES256 -Key $ec -Header @{ kid = 'ec-1' }

    # Path 2: let New-Jwt generate the key and return it
    # $bundle = New-Jwt -Payload @{ sub = 'app' } -Algorithm ES256 -GenerateKey -GeneratedKeyId 'ec-1' -IncludeGeneratedKey
    # $token = $bundle.Token
    # $ec = $bundle.Key

    $kid = (Get-JwtHeader -Token $token).kid
    $key = Get-JwtKeyFromSet -KeySet $set -KeyId $kid

    Test-Jwt -Token $token -Key $key -RequireExpiration $false
} finally {
    $rsa.Dispose()
    $ec.Dispose()
}
