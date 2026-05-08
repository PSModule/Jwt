[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Required for Pester tests'
)]
[CmdletBinding()]
param()

BeforeAll {
    # RSA key — used for RS256/RS384/RS512/PS256/PS384/PS512
    $script:rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $script:rsaPrivatePem = $script:rsa.ExportPkcs8PrivateKeyPem()
    $script:rsaPublicPem = $script:rsa.ExportSubjectPublicKeyInfoPem()

    # EC P-256 — ES256
    $script:ecdsa = [System.Security.Cryptography.ECDsa]::Create(
        [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    $script:ecPrivatePem = $script:ecdsa.ExportPkcs8PrivateKeyPem()
    $script:ecPublicPem = $script:ecdsa.ExportSubjectPublicKeyInfoPem()

    # EC P-384 — ES384
    $script:ecdsa384 = [System.Security.Cryptography.ECDsa]::Create(
        [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP384'))
    $script:ec384PrivatePem = $script:ecdsa384.ExportPkcs8PrivateKeyPem()
    $script:ec384PublicPem = $script:ecdsa384.ExportSubjectPublicKeyInfoPem()

    # EC P-521 — ES512
    $script:ecdsa521 = [System.Security.Cryptography.ECDsa]::Create(
        [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP521'))
    $script:ec521PrivatePem = $script:ecdsa521.ExportPkcs8PrivateKeyPem()
    $script:ec521PublicPem = $script:ecdsa521.ExportSubjectPublicKeyInfoPem()

    # Symmetric secrets — HS256/HS384/HS512
    $script:hmacSecret = [System.Text.Encoding]::UTF8.GetBytes('a-very-long-shared-secret-for-hmac-256-tests')
    $script:hmacSecret384 = [System.Text.Encoding]::UTF8.GetBytes(
        'a-very-long-shared-secret-for-hmac-384-tests-at-least-48-bytes'
    )
    $script:hmacSecret512 = [System.Text.Encoding]::UTF8.GetBytes(
        'a-very-long-shared-secret-for-hmac-512-tests-that-is-at-least-64-bytes-long-enough'
    )

    $script:basePayload = @{
        iss = 'https://issuer.example.com'
        sub = 'user-1'
        aud = 'api://test'
        exp = [DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds()
        nbf = [DateTimeOffset]::UtcNow.AddMinutes(-1).ToUnixTimeSeconds()
        iat = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }
}

AfterAll {
    if ($null -ne $script:rsa) { $script:rsa.Dispose() }
    if ($null -ne $script:ecdsa) { $script:ecdsa.Dispose() }
    if ($null -ne $script:ecdsa384) { $script:ecdsa384.Dispose() }
    if ($null -ne $script:ecdsa521) { $script:ecdsa521.Dispose() }
}

Describe 'New-Jwt' {
    It 'creates a signed RS256 token that round-trips and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem -Algorithm RS256
        $jwt | Should -BeOfType ([Jwt])
        $jwt.Header.alg | Should -Be 'RS256'
        $jwt.Header.typ | Should -Be 'JWT'
        $jwt.Signature | Should -Not -BeNullOrEmpty
        $jwt.ToString() | Should -Match '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
        Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'produces an unsigned token whose ToString ends with a trailing dot' {
        $jwt = New-Jwt -Payload $script:basePayload -Unsigned
        $jwt.Signature | Should -BeNullOrEmpty
        $jwt.ToString() | Should -Match '\.$'
        $jwt.SigningInput() | Should -Not -Match '\.$'
    }

    It 'signs with HS256 + byte[] secret and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -Audience 'api://test' | Should -BeTrue
    }

    It 'signs with HS256 + string secret and verifies' {
        $secret = 'plain-string-secret-1234567890'
        $jwt = New-Jwt -Payload $script:basePayload -Key $secret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $secret -Audience 'api://test' | Should -BeTrue
    }

    It 'signs with ES256 + EC PEM and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:ecPrivatePem -Algorithm ES256
        Test-Jwt -Token $jwt.ToString() -Key $script:ecPublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'merges custom kid into the header' {
        $jwt = New-Jwt -Header @{ kid = 'key-1' } -Payload $script:basePayload -Key $script:rsaPrivatePem
        $jwt.Header.kid | Should -Be 'key-1'
        $jwt.Header.alg | Should -Be 'RS256'
    }

    It 'recognizes registered claims on the payload' {
        $jwt = New-Jwt -Payload $script:basePayload -Unsigned
        $jwt.Payload.iss | Should -Be 'https://issuer.example.com'
        $jwt.Payload.sub | Should -Be 'user-1'
        $jwt.Payload.exp | Should -Be $script:basePayload.exp
    }

    It 'preserves nested claim values without truncation' {
        $payload = @{
            iss    = 'app'
            exp    = [DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds()
            groups = @(
                @{ name = 'admins'; rights = @('read', 'write', 'admin') }
                @{ name = 'devs'; rights = @('read', 'write') }
            )
        }
        $jwt = New-Jwt -Payload $payload -Key $script:hmacSecret -Algorithm HS256
        $parsed = ConvertFrom-Jwt -Token $jwt.ToString()
        $parsed.Payload.AdditionalFields['groups'].Count | Should -Be 2
        $parsed.Payload.AdditionalFields['groups'][0]['rights'].Count | Should -Be 3
    }
}

Describe 'ConvertFrom-Jwt round-trip and parsing' {
    It 'round-trips New-Jwt -> ToString -> ConvertFrom-Jwt' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem
        $compact = $jwt.ToString()
        $parsed = ConvertFrom-Jwt -Token $compact
        $parsed.EncodedHeader | Should -Be $jwt.EncodedHeader
        $parsed.EncodedPayload | Should -Be $jwt.EncodedPayload
        $parsed.Signature | Should -Be $jwt.Signature
        $parsed.ToString() | Should -Be $compact
    }

    It 'rejects a token with the wrong number of segments' {
        { ConvertFrom-Jwt -Token 'a.b' } | Should -Throw
        { ConvertFrom-Jwt -Token 'a.b.c.d' } | Should -Throw
    }

    It 'rejects non-Base64URL characters' {
        { ConvertFrom-Jwt -Token '!!!.bbb.ccc' } | Should -Throw
    }

    It 'rejects valid Base64URL but invalid JSON in the header' {
        $bad = [Convert]::ToBase64String([byte[]](0xFF, 0xFE, 0xFD)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $payloadSeg = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"a":1}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        { ConvertFrom-Jwt -Token "$bad.$payloadSeg.x" } | Should -Throw
    }

    It 'rejects an empty header segment' {
        { ConvertFrom-Jwt -Token '.bbb.ccc' } | Should -Throw
    }

    It 'accepts a string token via the pipeline' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        $parsed = $jwt.ToString() | ConvertFrom-Jwt
        $parsed.Header.alg | Should -Be 'HS256'
    }
}

Describe 'Test-Jwt validation' {
    It 'returns $true for a valid token' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem
        Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem -Issuer 'https://issuer.example.com' -Audience 'api://test' | Should -BeTrue
    }

    It 'returns $false for an expired token' {
        $payload = @{ iss = 'a'; exp = [DateTimeOffset]::UtcNow.AddMinutes(-10).ToUnixTimeSeconds() }
        $jwt = New-Jwt -Payload $payload -Key $script:hmacSecret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret | Should -BeFalse
    }

    It 'returns $false for a not-yet-valid token' {
        $payload = @{
            iss = 'a'
            nbf = [DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds()
            exp = [DateTimeOffset]::UtcNow.AddMinutes(20).ToUnixTimeSeconds()
        }
        $jwt = New-Jwt -Payload $payload -Key $script:hmacSecret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret | Should -BeFalse
    }

    It 'returns $false for a wrong issuer' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -Issuer 'other' | Should -BeFalse
    }

    It 'returns $false for a wrong audience' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -Audience 'wrong' | Should -BeFalse
    }

    It 'matches array-typed aud when at least one entry matches' {
        $payload = @{
            iss = 'a'
            aud = @('a', 'b', 'c')
            exp = [DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds()
        }
        $jwt = New-Jwt -Payload $payload -Key $script:hmacSecret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -Audience 'b' | Should -BeTrue
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -Audience 'z' | Should -BeFalse
    }

    It 'returns $false for a tampered signature' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        $compact = $jwt.ToString()
        $lastChar = $compact[$compact.Length - 1]
        $replacement = if ($lastChar -eq 'A') { 'B' } else { 'A' }
        $tampered = $compact.Substring(0, $compact.Length - 1) + $replacement
        Test-Jwt -Token $tampered -Key $script:hmacSecret -Audience 'api://test' | Should -BeFalse
    }

    It 'tolerates clock skew within the supplied window' {
        $payload = @{ iss = 'a'; exp = [DateTimeOffset]::UtcNow.AddSeconds(-5).ToUnixTimeSeconds() }
        $jwt = New-Jwt -Payload $payload -Key $script:hmacSecret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -ClockSkew ([timespan]::FromSeconds(30)) | Should -BeTrue
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -ClockSkew ([timespan]::FromSeconds(1)) | Should -BeFalse
    }

    It 'tolerates nbf clock skew within the supplied window' {
        $payload = @{
            iss = 'a'
            nbf = [DateTimeOffset]::UtcNow.AddSeconds(5).ToUnixTimeSeconds()
            exp = [DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds()
        }
        $jwt = New-Jwt -Payload $payload -Key $script:hmacSecret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -ClockSkew ([timespan]::FromSeconds(30)) | Should -BeTrue
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -ClockSkew ([timespan]::FromSeconds(1)) | Should -BeFalse
    }

    It 'rejects HS256 + RSA public key (algorithm-confusion attack)' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        { Test-Jwt -Token $jwt.ToString() -Key $script:rsa } | Should -Throw '*HS256*symmetric*'
    }

    It 'rejects an HS256 token validated with a PEM-formatted string' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        { Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem } | Should -Throw '*HS256*PEM*'
    }

    It 'rejects unknown algorithms' {
        $headerJson = '{"alg":"FOO","typ":"JWT"}'
        $h = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $p = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"a":1}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        { Test-Jwt -Token "$h.$p.x" -Key $script:hmacSecret } | Should -Throw '*FOO*'
    }

    It 'rejects a token with a missing alg header' {
        $headerJson = '{"typ":"JWT"}'
        $h = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $p = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"a":1}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        { Test-Jwt -Token "$h.$p.x" -Key $script:hmacSecret } | Should -Throw '*alg*'
    }

    It 'with -Detailed reports a structured per-check result' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem
        $result = Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem -Audience 'api://test' -Detailed
        $result.Valid | Should -BeTrue
        $result.SignatureValidated | Should -BeTrue
        $result.Algorithm | Should -Be 'RS256'
        $result.Checks | Where-Object { $_.Name -eq 'Signature' } | Select-Object -ExpandProperty Passed | Should -BeTrue
    }

    It 'with -AllowUnsigned accepts alg=none and reports SignatureValidated=$false' {
        $headerJson = '{"alg":"none","typ":"JWT"}'
        $payloadJson = ConvertTo-Json -InputObject $script:basePayload -Depth 100 -Compress
        $h = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $p = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $token = "$h.$p."
        $result = Test-Jwt -Token $token -AllowUnsigned -Audience 'api://test' -Detailed
        $result.SignatureValidated | Should -BeFalse
        ($result.Checks | Where-Object { $_.Name -eq 'Signature' }).Reason | Should -Be 'Skipped (unsigned token)'
    }

    It 'rejects alg=none without -AllowUnsigned' {
        $headerBytes = [System.Text.Encoding]::UTF8.GetBytes('{"alg":"none","typ":"JWT"}')
        $h = [Convert]::ToBase64String($headerBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes('{"a":1}')
        $p = [Convert]::ToBase64String($payloadBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        { Test-Jwt -Token "$h.$p." -Key $script:hmacSecret } | Should -Throw
    }
}

Describe 'All signing algorithms — sign and verify round-trip' {
    It 'RS256 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem -Algorithm RS256
        Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'RS384 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem -Algorithm RS384
        Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'RS512 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem -Algorithm RS512
        Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'PS256 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem -Algorithm PS256
        Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'PS384 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem -Algorithm PS384
        Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'PS512 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem -Algorithm PS512
        Test-Jwt -Token $jwt.ToString() -Key $script:rsaPublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'HS256 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret -Audience 'api://test' | Should -BeTrue
    }

    It 'HS384 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret384 -Algorithm HS384
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret384 -Audience 'api://test' | Should -BeTrue
    }

    It 'HS512 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret512 -Algorithm HS512
        Test-Jwt -Token $jwt.ToString() -Key $script:hmacSecret512 -Audience 'api://test' | Should -BeTrue
    }

    It 'ES256 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:ecPrivatePem -Algorithm ES256
        Test-Jwt -Token $jwt.ToString() -Key $script:ecPublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'ES384 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:ec384PrivatePem -Algorithm ES384
        Test-Jwt -Token $jwt.ToString() -Key $script:ec384PublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'ES512 signs and verifies' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:ec521PrivatePem -Algorithm ES512
        Test-Jwt -Token $jwt.ToString() -Key $script:ec521PublicPem -Audience 'api://test' | Should -BeTrue
    }

    It 'all algorithms produce the correct alg header value' {
        $algs = @('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512')
        $keys = @{
            RS256 = $script:rsaPrivatePem; RS384 = $script:rsaPrivatePem; RS512 = $script:rsaPrivatePem
            PS256 = $script:rsaPrivatePem; PS384 = $script:rsaPrivatePem; PS512 = $script:rsaPrivatePem
            HS256 = $script:hmacSecret; HS384 = $script:hmacSecret384; HS512 = $script:hmacSecret512
            ES256 = $script:ecPrivatePem; ES384 = $script:ec384PrivatePem; ES512 = $script:ec521PrivatePem
        }
        foreach ($alg in $algs) {
            $jwt = New-Jwt -Payload $script:basePayload -Key $keys[$alg] -Algorithm $alg
            $jwt.Header.alg | Should -Be $alg -Because "header alg should be $alg"
        }
    }
}

Describe 'JWK conversion' {
    It 'round-trips an RSA key' {
        $jwk = ConvertTo-JwtKey -Key $script:rsa -IncludePrivate -Use 'sig' -Alg 'RS256' -Kid 'k1'
        $jwk.kty | Should -Be 'RSA'
        $jwk.n | Should -Not -BeNullOrEmpty
        $jwk.e | Should -Not -BeNullOrEmpty
        $jwk.d | Should -Not -BeNullOrEmpty
        $rsa2 = ConvertFrom-JwtKey -JwtKey $jwk
        try {
            $jwt = New-Jwt -Payload $script:basePayload -Key $script:rsaPrivatePem
            Test-Jwt -Token $jwt.ToString() -Key $rsa2 -Audience 'api://test' | Should -BeTrue
        } finally { $rsa2.Dispose() }
    }

    It 'round-trips an EC P-256 key' {
        $jwk = ConvertTo-JwtKey -Key $script:ecdsa -IncludePrivate
        $jwk.kty | Should -Be 'EC'
        $jwk.crv | Should -Be 'P-256'
        $ec2 = ConvertFrom-JwtKey -JwtKey $jwk
        try {
            $jwt = New-Jwt -Payload $script:basePayload -Key $script:ecPrivatePem -Algorithm ES256
            Test-Jwt -Token $jwt.ToString() -Key $ec2 -Audience 'api://test' | Should -BeTrue
        } finally { $ec2.Dispose() }
    }

    It 'round-trips an EC P-384 key' {
        $jwk = ConvertTo-JwtKey -Key $script:ecdsa384 -IncludePrivate
        $jwk.kty | Should -Be 'EC'
        $jwk.crv | Should -Be 'P-384'
        $ec2 = ConvertFrom-JwtKey -JwtKey $jwk
        try {
            $jwt = New-Jwt -Payload $script:basePayload -Key $script:ec384PrivatePem -Algorithm ES384
            Test-Jwt -Token $jwt.ToString() -Key $ec2 -Audience 'api://test' | Should -BeTrue
        } finally { $ec2.Dispose() }
    }

    It 'round-trips an EC P-521 key' {
        $jwk = ConvertTo-JwtKey -Key $script:ecdsa521 -IncludePrivate
        $jwk.kty | Should -Be 'EC'
        $jwk.crv | Should -Be 'P-521'
        $ec2 = ConvertFrom-JwtKey -JwtKey $jwk
        try {
            $jwt = New-Jwt -Payload $script:basePayload -Key $script:ec521PrivatePem -Algorithm ES512
            Test-Jwt -Token $jwt.ToString() -Key $ec2 -Audience 'api://test' | Should -BeTrue
        } finally { $ec2.Dispose() }
    }

    It 'round-trips an HMAC (oct) key' {
        $jwk = ConvertTo-JwtKey -Key $script:hmacSecret
        $jwk.kty | Should -Be 'oct'
        $bytes = ConvertFrom-JwtKey -JwtKey $jwk
        [System.Linq.Enumerable]::SequenceEqual([byte[]]$bytes, [byte[]]$script:hmacSecret) | Should -BeTrue
    }
}

Describe 'Inspection helpers' {
    It 'Get-JwtHeader returns the parsed header from a string' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        $h = $jwt.ToString() | Get-JwtHeader
        $h.alg | Should -Be 'HS256'
    }

    It 'Get-JwtPayload returns the parsed payload from a string' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        $p = $jwt.ToString() | Get-JwtPayload
        $p.iss | Should -Be 'https://issuer.example.com'
    }

    It 'Get-JwtClaim returns a single value when given a single name' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        $jwt.ToString() | Get-JwtClaim -Name 'iss' | Should -Be 'https://issuer.example.com'
    }

    It 'Get-JwtClaim returns $null silently for a missing single name' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        ($jwt.ToString() | Get-JwtClaim -Name 'absent') | Should -BeNullOrEmpty
    }

    It 'Get-JwtClaim returns an ordered hashtable for multiple names with $null for missing' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        $r = $jwt.ToString() | Get-JwtClaim -Name 'iss', 'absent'
        $r['iss'] | Should -Be 'https://issuer.example.com'
        $r.Contains('absent') | Should -BeTrue
        $r['absent'] | Should -BeNullOrEmpty
    }

    It 'Get-JwtClaim emits a non-terminating error per missing name with -ErrorIfMissing' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        $errs = $null
        $null = $jwt.ToString() | Get-JwtClaim -Name 'absent', 'missing' -ErrorIfMissing -ErrorVariable errs -ErrorAction SilentlyContinue
        $errs.Count | Should -Be 2
    }

    It 'reads private claims from AdditionalFields' {
        $payload = $script:basePayload.Clone()
        $payload['scope'] = 'read write'
        $jwt = New-Jwt -Payload $payload -Key $script:hmacSecret -Algorithm HS256
        $jwt.ToString() | Get-JwtClaim -Name 'scope' | Should -Be 'read write'
    }
}

Describe 'Pipeline binding' {
    It 'Test-Jwt accepts a string via pipeline' {
        $jwt = New-Jwt -Payload $script:basePayload -Key $script:hmacSecret -Algorithm HS256
        $jwt.ToString() | Test-Jwt -Key $script:hmacSecret -Audience 'api://test' | Should -BeTrue
    }
}

Describe 'Known external test vectors (jwt.io samples)' {
    BeforeAll {
        $hs256Token = @(
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0'
            'KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30'
        ) -join '.'
        $script:vectorHs256 = @{
            Token  = $hs256Token
            Secret = 'a-string-secret-at-least-256-bits-long'
        }
        $hs384Token = @(
            'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9'
            'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0'
            'owv7q9nVbW5tqUezF_G2nHTra-ANW3HqW9epyVwh08Y-Z-FKsnG8eBIpC4GTfTVU'
        ) -join '.'
        $script:vectorHs384 = @{
            Token  = $hs384Token
            Secret = 'a-valid-string-secret-that-is-at-least-384-bits-long'
        }
        $es512Sig = -join @(
            'AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9T'
            'ksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk'
        )
        $script:vectorEs512Token = @(
            'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9'
            'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0'
            $es512Sig
        ) -join '.'
        $script:vectorEs512PublicKey = @'
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----
'@
    }

    It 'parses and verifies the HS256 vector' {
        $parsed = $script:vectorHs256.Token | ConvertFrom-Jwt
        $parsed.Header.alg | Should -Be 'HS256'
        $parsed.Payload.sub | Should -Be '1234567890'
        $parsed.Payload.iat | Should -Be 1516239022
        $parsed.Payload.AdditionalFields['name'] | Should -Be 'John Doe'
        $parsed.Payload.AdditionalFields['admin'] | Should -BeTrue
        Test-Jwt -Token $script:vectorHs256.Token -Key $script:vectorHs256.Secret -RequireExpiration $false | Should -BeTrue
    }

    It 'rejects the HS256 vector with the wrong secret' {
        Test-Jwt -Token $script:vectorHs256.Token -Key 'wrong-secret' -RequireExpiration $false | Should -BeFalse
    }

    It 'parses and verifies the HS384 vector' {
        $parsed = $script:vectorHs384.Token | ConvertFrom-Jwt
        $parsed.Header.alg | Should -Be 'HS384'
        $parsed.Payload.sub | Should -Be '1234567890'
        $parsed.Payload.AdditionalFields['name'] | Should -Be 'John Doe'
        Test-Jwt -Token $script:vectorHs384.Token -Key $script:vectorHs384.Secret -RequireExpiration $false | Should -BeTrue
    }

    It 'rejects the HS384 vector with the wrong secret' {
        Test-Jwt -Token $script:vectorHs384.Token -Key 'wrong-secret' -RequireExpiration $false | Should -BeFalse
    }

    It 'parses and verifies the ES512 vector against the documented public key' {
        $parsed = $script:vectorEs512Token | ConvertFrom-Jwt
        $parsed.Header.alg | Should -Be 'ES512'
        $parsed.Payload.sub | Should -Be '1234567890'
        $parsed.Payload.AdditionalFields['admin'] | Should -BeTrue
        Test-Jwt -Token $script:vectorEs512Token -Key $script:vectorEs512PublicKey -RequireExpiration $false | Should -BeTrue
    }
}
