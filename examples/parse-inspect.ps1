$token = New-Jwt -Payload @{
    sub  = 'joe'
    role = 'admin'
} -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'

$compact = $token.ToString()
$parsed = ConvertFrom-Jwt -Token $compact

Get-JwtHeader -Token $compact
Get-JwtPayload -Token $compact
Get-JwtClaim -Token $compact -Name @('sub', 'role')

$parsed
