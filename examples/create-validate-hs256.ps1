$secret = 'a-string-secret-at-least-256-bits-long'

$jwt = New-Jwt -Payload @{
    sub = 'user@example.com'
    iss = 'https://issuer.example'
    aud = 'api'
    exp = [DateTimeOffset]::UtcNow.AddMinutes(15).ToUnixTimeSeconds()
} -Algorithm HS256 -Key $secret

Test-Jwt -Token $jwt -Key $secret -Issuer 'https://issuer.example' -Audience 'api'
