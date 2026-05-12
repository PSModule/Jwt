[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Required for Pester tests'
)]
[CmdletBinding()]
param()

# The Process-PSModule test harness builds the Jwt module and auto-imports it before
# this script runs, so no Import-Module call is needed here.

$testCases = . "$PSScriptRoot/Data/TestCases.ps1"

Describe 'Jwt module' {
    Context 'Data-driven HS256 cases - <Name>' -ForEach $testCases {
        It 'New-Jwt produces a token whose signing input matches the expected encoded segments' {
            $payloadHash = [ordered]@{}
            foreach ($k in $Payload.Keys) { $payloadHash[$k] = $Payload[$k] }
            $headerHash = [ordered]@{}
            foreach ($k in $Header.Keys) { if ($k -ne 'alg') { $headerHash[$k] = $Header[$k] } }

            $jwt = New-Jwt -Header $headerHash -Payload $payloadHash -Algorithm $Algorithm -Key $Secret

            $jwt.GetType().Name | Should -Be 'Jwt'
            $jwt.Header.alg | Should -Be $Algorithm
            $jwt.Header.typ | Should -Be 'JWT'
            if ($EncodedHeader) { $jwt.EncodedHeader | Should -Be $EncodedHeader }
            if ($EncodedPayload) { $jwt.EncodedPayload | Should -Be $EncodedPayload }
            if ($EncodedSig) { $jwt.Signature | Should -Be $EncodedSig }
        }

        It 'Test-Jwt validates a freshly signed token' {
            $payloadHash = @{}
            foreach ($k in $Payload.Keys) { $payloadHash[$k] = $Payload[$k] }
            $jwt = New-Jwt -Payload $payloadHash -Algorithm $Algorithm -Key $Secret

            Test-Jwt -Token $jwt -Key $Secret -RequireExpiration $false | Should -BeTrue
        }

        It 'ConvertFrom-Jwt round-trips the compact form' {
            $payloadHash = @{}
            foreach ($k in $Payload.Keys) { $payloadHash[$k] = $Payload[$k] }
            $jwt = New-Jwt -Payload $payloadHash -Algorithm $Algorithm -Key $Secret
            $compact = $jwt.ToString()

            $parsed = ConvertFrom-Jwt -Token $compact
            $parsed.ToString() | Should -Be $compact
            $parsed.EncodedHeader | Should -Be $jwt.EncodedHeader
            $parsed.EncodedPayload | Should -Be $jwt.EncodedPayload
            $parsed.Signature | Should -Be $jwt.Signature
        }
    }

    Context 'Creation - signed and unsigned modes' {
        It 'New-Jwt -Unsigned produces a token with empty signature and a trailing dot' {
            $jwt = New-Jwt -Payload @{ sub = 'app' } -Algorithm RS256 -Unsigned

            $jwt.GetType().Name | Should -Be 'Jwt'
            $jwt.Signature | Should -Be ''
            $jwt.ToString() | Should -Match '\.$'
            $jwt.SigningInput() | Should -Be ($jwt.EncodedHeader + '.' + $jwt.EncodedPayload)
        }

        It 'New-Jwt accepts HS256 with a byte[] secret' {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long')
            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $bytes

            Test-Jwt -Token $jwt -Key $bytes -RequireExpiration $false | Should -BeTrue
        }

        It 'New-Jwt with HS256 and a SecureString raw secret round-trips' {
            $secret = ConvertTo-SecureString 'a-string-secret-at-least-256-bits-long' -AsPlainText -Force
            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $secret
            Test-Jwt -Token $jwt -Key $secret -RequireExpiration $false | Should -BeTrue
        }

        It 'New-Jwt RS256 with a generated RSA key round-trips' {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            try {
                $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm RS256 -Key $rsa
                Test-Jwt -Token $jwt -Key $rsa -RequireExpiration $false | Should -BeTrue
            } finally { $rsa.Dispose() }
        }

        It 'New-Jwt ES256 with a generated EC P-256 key round-trips' {
            $ecdsa = [System.Security.Cryptography.ECDsa]::Create(
                [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
            try {
                $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm ES256 -Key $ecdsa
                Test-Jwt -Token $jwt -Key $ecdsa -RequireExpiration $false | Should -BeTrue
            } finally { $ecdsa.Dispose() }
        }

        It 'New-Jwt merges custom header fields like kid' {
            $jwt = New-Jwt -Header @{ kid = 'key-1' } -Payload @{ sub = 'joe' } `
                -Algorithm HS256 -Key 'super-secret'
            $jwt.Header.kid | Should -Be 'key-1'
            $jwt.Header.alg | Should -Be 'HS256'
            $jwt.Header.typ | Should -Be 'JWT'
        }

        It 'New-Jwt preserves nested claim structure (no -Depth 2 truncation)' {
            $payload = @{
                sub    = 'joe'
                groups = @(
                    @{ id = 1; name = 'admins'; meta = @{ source = 'aad'; tier = 'gold' } },
                    @{ id = 2; name = 'users'; meta = @{ source = 'aad'; tier = 'silver' } }
                )
            }
            $jwt = New-Jwt -Payload $payload -Algorithm HS256 -Key 'super-secret'
            $parsed = ConvertFrom-Jwt -Token $jwt.ToString()
            $groups = $parsed.Payload.AdditionalFields['groups']
            $groups.Count | Should -Be 2
            $groups[0].meta.source | Should -Be 'aad'
        }
    }

    Context 'Parsing - malformed inputs' {
        It 'rejects a token with too few segments' {
            { ConvertFrom-Jwt -Token 'a.b' } | Should -Throw '*3 segments*'
        }

        It 'rejects a token with too many segments' {
            { ConvertFrom-Jwt -Token 'a.b.c.d' } | Should -Throw '*3 segments*'
        }

        It 'rejects an empty header segment' {
            { ConvertFrom-Jwt -Token '.abc.def' } | Should -Throw '*header segment is empty*'
        }

        It 'rejects an empty payload segment' {
            $h = ConvertTo-Base64UrlString '{"alg":"HS256"}'
            { ConvertFrom-Jwt -Token "$h..sig" } | Should -Throw '*payload segment is empty*'
        }

        It 'rejects a header that is not valid JSON' {
            $h = ConvertTo-Base64UrlString 'not-json'
            $p = ConvertTo-Base64UrlString '{}'
            { ConvertFrom-Jwt -Token "$h.$p.sig" } | Should -Throw '*header*not valid JSON*'
        }

        It 'rejects a payload that is not valid JSON' {
            $h = ConvertTo-Base64UrlString '{"alg":"HS256"}'
            $p = ConvertTo-Base64UrlString 'not-json'
            { ConvertFrom-Jwt -Token "$h.$p.sig" } | Should -Throw '*payload*not valid JSON*'
        }

        It 'rejects non-base64url characters in segments' {
            { ConvertFrom-Jwt -Token '!!!.???.sig' } | Should -Throw '*invalid base64url*'
        }
    }

    Context 'Validation - signature outcomes' {
        BeforeAll {
            $script:secret = 'a-string-secret-at-least-256-bits-long'
            $script:goodJwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $script:secret
        }

        It 'returns true for a valid HS256 token' {
            Test-Jwt -Token $script:goodJwt -Key $script:secret -RequireExpiration $false | Should -BeTrue
        }

        It 'returns false for a tampered signature' {
            $compact = $script:goodJwt.ToString()
            $parts = $compact.Split('.')
            $parts[2] = ConvertTo-Base64UrlString ([byte[]](1..32))
            $tampered = $parts -join '.'
            Test-Jwt -Token $tampered -Key $script:secret -RequireExpiration $false | Should -BeFalse
        }

        It 'returns false for a tampered payload' {
            $compact = $script:goodJwt.ToString()
            $parts = $compact.Split('.')
            $parts[1] = ConvertTo-Base64UrlString '{"sub":"attacker"}'
            $tampered = $parts -join '.'
            Test-Jwt -Token $tampered -Key $script:secret -RequireExpiration $false | Should -BeFalse
        }
    }

    Context 'Validation - claim outcomes' {
        BeforeAll {
            $script:secret = 'a-string-secret-at-least-256-bits-long'
            $script:nowSec = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        }

        It 'fails when the token has expired' {
            $jwt = New-Jwt -Payload @{ sub = 'joe'; exp = $script:nowSec - 60 } `
                -Algorithm HS256 -Key $script:secret
            Test-Jwt -Token $jwt -Key $script:secret | Should -BeFalse
        }

        It 'passes when expired within the clock skew window' {
            $jwt = New-Jwt -Payload @{ sub = 'joe'; exp = $script:nowSec - 30 } `
                -Algorithm HS256 -Key $script:secret
            Test-Jwt -Token $jwt -Key $script:secret -ClockSkew ([timespan]::FromMinutes(5)) | Should -BeTrue
        }

        It 'fails when expired beyond the clock skew window' {
            $jwt = New-Jwt -Payload @{ sub = 'joe'; exp = $script:nowSec - 600 } `
                -Algorithm HS256 -Key $script:secret
            Test-Jwt -Token $jwt -Key $script:secret -ClockSkew ([timespan]::FromMinutes(5)) | Should -BeFalse
        }

        It 'fails when nbf is in the future' {
            $jwt = New-Jwt -Payload @{ sub = 'joe'; nbf = $script:nowSec + 600 } `
                -Algorithm HS256 -Key $script:secret
            Test-Jwt -Token $jwt -Key $script:secret -RequireExpiration $false | Should -BeFalse
        }

        It 'passes when nbf is in the future but within skew' {
            $jwt = New-Jwt -Payload @{ sub = 'joe'; nbf = $script:nowSec + 30 } `
                -Algorithm HS256 -Key $script:secret
            Test-Jwt -Token $jwt -Key $script:secret -RequireExpiration $false `
                -ClockSkew ([timespan]::FromMinutes(5)) | Should -BeTrue
        }

        It 'fails when issuer does not match' {
            $jwt = New-Jwt -Payload @{ sub = 'joe'; iss = 'a' } `
                -Algorithm HS256 -Key $script:secret
            Test-Jwt -Token $jwt -Key $script:secret -RequireExpiration $false -Issuer 'b' | Should -BeFalse
        }

        It 'passes when audience matches a single-string aud' {
            $jwt = New-Jwt -Payload @{ sub = 'joe'; aud = 'api' } `
                -Algorithm HS256 -Key $script:secret
            Test-Jwt -Token $jwt -Key $script:secret -RequireExpiration $false `
                -Audience 'api' | Should -BeTrue
        }

        It 'passes when any supplied audience appears in an array aud' {
            $jwt = New-Jwt -Payload @{ sub = 'joe'; aud = @('a', 'b') } `
                -Algorithm HS256 -Key $script:secret
            Test-Jwt -Token $jwt -Key $script:secret -RequireExpiration $false `
                -Audience @('x', 'b', 'y') | Should -BeTrue
        }

        It 'fails when no supplied audience matches' {
            $jwt = New-Jwt -Payload @{ sub = 'joe'; aud = @('a', 'b') } `
                -Algorithm HS256 -Key $script:secret
            Test-Jwt -Token $jwt -Key $script:secret -RequireExpiration $false `
                -Audience @('x', 'y') | Should -BeFalse
        }
    }

    Context 'Validation - alg, none, and algorithm-confusion' {
        It "rejects an alg value that is not in the supported set" {
            $h = ConvertTo-Base64UrlString '{"alg":"HS999","typ":"JWT"}'
            $p = ConvertTo-Base64UrlString '{"sub":"joe"}'
            { Test-Jwt -Token "$h.$p.sig" -Key 'super-secret' } | Should -Throw '*not supported*'
        }

        It "rejects a token with a missing alg claim" {
            $h = ConvertTo-Base64UrlString '{"typ":"JWT"}'
            $p = ConvertTo-Base64UrlString '{"sub":"joe"}'
            { Test-Jwt -Token "$h.$p.sig" -Key 'super-secret' } | Should -Throw "*missing the 'alg'*"
        }

        It "rejects alg=none by default" {
            $h = ConvertTo-Base64UrlString '{"alg":"none","typ":"JWT"}'
            $p = ConvertTo-Base64UrlString '{"sub":"joe"}'
            { Test-Jwt -Token "$h.$p." } | Should -Throw "*'none'*"
        }

        It "accepts alg=none with -AllowUnsigned and reports SignatureValidated=false" {
            $h = ConvertTo-Base64UrlString '{"alg":"none","typ":"JWT"}'
            $p = ConvertTo-Base64UrlString '{"sub":"joe"}'
            $result = Test-Jwt -Token "$h.$p." -AllowUnsigned -RequireExpiration $false -Detailed
            $result.Valid | Should -BeTrue
            $result.SignatureValidated | Should -BeFalse
            ($result.Checks | Where-Object Name -EQ 'Signature').Reason | Should -Be 'Skipped (unsigned token)'
        }

        It "blocks the HS256+RSA-public-key algorithm-confusion attack" {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            try {
                $pem = $rsa.ExportSubjectPublicKeyInfoPem()
                $h = ConvertTo-Base64UrlString '{"alg":"HS256","typ":"JWT"}'
                $p = ConvertTo-Base64UrlString '{"sub":"attacker"}'
                $sig = ConvertTo-Base64UrlString ([byte[]](1..32))
                { Test-Jwt -Token "$h.$p.$sig" -Key $pem } | Should -Throw '*HS256*'
            } finally { $rsa.Dispose() }
        }
    }

    Context 'Test-Jwt -Detailed output shape' {
        It 'returns a stable Checks array indexable by Name' {
            $secret = 'a-string-secret-at-least-256-bits-long'
            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $secret
            $r = Test-Jwt -Token $jwt -Key $secret -RequireExpiration $false -Detailed

            $r | Should -BeOfType [pscustomobject]
            $r.Valid | Should -BeTrue
            $r.SignatureValidated | Should -BeTrue
            $r.Algorithm | Should -Be 'HS256'
            $r.Checks.Count | Should -Be 6
            ($r.Checks | ForEach-Object Name) | Should -Be @(
                'Algorithm', 'Signature', 'Expiration', 'NotBefore', 'Issuer', 'Audience'
            )
        }
    }

    Context 'Get-JwtClaim' {
        BeforeAll {
            $script:jwt = New-Jwt -Payload @{ sub = 'joe'; role = 'admin'; iat = 1516239022 } `
                -Algorithm HS256 -Key 'super-secret'
        }

        It 'returns the value of a present registered claim' {
            Get-JwtClaim -Token $script:jwt -Name 'sub' | Should -Be 'joe'
        }

        It 'returns the value of a present private claim' {
            Get-JwtClaim -Token $script:jwt -Name 'role' | Should -Be 'admin'
        }

        It 'returns the value of a numeric registered claim' {
            Get-JwtClaim -Token $script:jwt -Name 'iat' | Should -Be 1516239022
        }

        It 'returns $null silently for a missing single name' {
            Get-JwtClaim -Token $script:jwt -Name 'missing' | Should -BeNullOrEmpty
        }

        It 'returns an ordered hashtable for an array of names with $null for missing' {
            $r = Get-JwtClaim -Token $script:jwt -Name @('sub', 'missing', 'role')
            $r['sub'] | Should -Be 'joe'
            $r['role'] | Should -Be 'admin'
            $r['missing'] | Should -BeNullOrEmpty
            @($r.Keys) | Should -Be @('sub', 'missing', 'role')
        }

        It '-ErrorIfMissing emits a non-terminating error per missing name' {
            $err = $null
            Get-JwtClaim -Token $script:jwt -Name 'missing' -ErrorIfMissing -ErrorVariable err -ErrorAction SilentlyContinue
            $err.Count | Should -BeGreaterThan 0
            $err[0].ToString() | Should -Match 'missing'
        }
    }

    Context 'Pipeline binding' {
        It 'accepts a token via the pipeline for ConvertFrom-Jwt' {
            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'super-secret'
            $compact = $jwt.ToString()
            ($compact | ConvertFrom-Jwt).Payload.sub | Should -Be 'joe'
        }

        It 'accepts a token via the pipeline for Get-JwtHeader / Get-JwtPayload / Get-JwtClaim' {
            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'super-secret'
            $compact = $jwt.ToString()
            ($compact | Get-JwtHeader).alg | Should -Be 'HS256'
            ($compact | Get-JwtPayload).sub | Should -Be 'joe'
            ($compact | Get-JwtClaim -Name 'sub') | Should -Be 'joe'
        }

        It 'accepts a token via the pipeline for Test-Jwt' {
            $secret = 'a-string-secret-at-least-256-bits-long'
            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $secret
            $jwt.ToString() | Test-Jwt -Key $secret -RequireExpiration $false | Should -BeTrue
        }
    }

    Context 'JWK round-trip' {
        It 'round-trips an RSA key through ConvertTo-JwtKey / ConvertFrom-JwtKey' {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            try {
                $jwk = ConvertTo-JwtKey -Key $rsa -IncludePrivateParameters
                $jwk.kty | Should -Be 'RSA'
                $jwk.n | Should -Not -BeNullOrEmpty
                $jwk.e | Should -Not -BeNullOrEmpty

                $rsa2 = ConvertFrom-JwtKey -Key $jwk
                try {
                    $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm RS256 -Key $rsa
                    Test-Jwt -Token $jwt -Key $rsa2 -RequireExpiration $false | Should -BeTrue
                } finally { $rsa2.Dispose() }
            } finally { $rsa.Dispose() }
        }

        It 'round-trips an EC P-256 key through ConvertTo-JwtKey / ConvertFrom-JwtKey' {
            $ecdsa = [System.Security.Cryptography.ECDsa]::Create(
                [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
            try {
                $jwk = ConvertTo-JwtKey -Key $ecdsa -IncludePrivateParameters
                $jwk.kty | Should -Be 'EC'
                $jwk.crv | Should -Be 'P-256'

                $ecdsa2 = ConvertFrom-JwtKey -Key $jwk
                try {
                    $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm ES256 -Key $ecdsa
                    Test-Jwt -Token $jwt -Key $ecdsa2 -RequireExpiration $false | Should -BeTrue
                } finally { $ecdsa2.Dispose() }
            } finally { $ecdsa.Dispose() }
        }

        It 'round-trips an HMAC byte[] key through ConvertTo-JwtKey / ConvertFrom-JwtKey' {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long')
            $jwk = ConvertTo-JwtKey -Key $bytes
            $jwk.kty | Should -Be 'oct'
            $jwk.k | Should -Not -BeNullOrEmpty

            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $bytes
            Test-Jwt -Token $jwt -Key $jwk -RequireExpiration $false | Should -BeTrue
        }
    }

    Context 'JWS algorithm coverage (RFC 7518 §3)' {
        BeforeAll {
            $script:secret = 'a-string-secret-at-least-256-bits-long'
            $script:rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $script:ec256 = [System.Security.Cryptography.ECDsa]::Create(
                [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
            $script:ec384 = [System.Security.Cryptography.ECDsa]::Create(
                [System.Security.Cryptography.ECCurve]::CreateFromValue('1.3.132.0.34'))
            $script:ec521 = [System.Security.Cryptography.ECDsa]::Create(
                [System.Security.Cryptography.ECCurve]::CreateFromValue('1.3.132.0.35'))
        }

        AfterAll {
            $script:rsa.Dispose()
            $script:ec256.Dispose()
            $script:ec384.Dispose()
            $script:ec521.Dispose()
        }

        It 'signs and verifies <Alg>' -ForEach @(
            @{ Alg = 'HS256' },
            @{ Alg = 'HS384' },
            @{ Alg = 'HS512' }
        ) {
            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm $Alg -Key $script:secret
            $jwt.Header.alg | Should -Be $Alg
            Test-Jwt -Token $jwt -Key $script:secret -RequireExpiration $false | Should -BeTrue
        }

        It 'signs and verifies <Alg>' -ForEach @(
            @{ Alg = 'RS256' },
            @{ Alg = 'RS384' },
            @{ Alg = 'RS512' },
            @{ Alg = 'PS256' },
            @{ Alg = 'PS384' },
            @{ Alg = 'PS512' }
        ) {
            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm $Alg -Key $script:rsa
            $jwt.Header.alg | Should -Be $Alg
            Test-Jwt -Token $jwt -Key $script:rsa -RequireExpiration $false | Should -BeTrue
        }

        It 'signs and verifies <Alg> with curve <Crv>' -ForEach @(
            @{ Alg = 'ES256'; Crv = 'P-256'; KeyVar = 'ec256' },
            @{ Alg = 'ES384'; Crv = 'P-384'; KeyVar = 'ec384' },
            @{ Alg = 'ES512'; Crv = 'P-521'; KeyVar = 'ec521' }
        ) {
            $key = (Get-Variable -Scope Script -Name $KeyVar -ValueOnly)
            $jwt = New-Jwt -Payload @{ sub = 'joe' } -Algorithm $Alg -Key $key
            $jwt.Header.alg | Should -Be $Alg
            Test-Jwt -Token $jwt -Key $key -RequireExpiration $false | Should -BeTrue
        }

        It 'rejects an EC key whose curve does not match the algorithm' {
            { New-Jwt -Payload @{ sub = 'x' } -Algorithm ES384 -Key $script:ec256 } |
                Should -Throw '*P-384*'
        }

        It 'rejects RS512 sign-attempts that use a HS512 key' {
            { New-Jwt -Payload @{ sub = 'x' } -Algorithm RS512 -Key $script:secret } |
                Should -Throw '*RS512*'
        }

        It 'PS256 signatures are not bit-identical across runs (PSS is randomized)' {
            $a = (New-Jwt -Payload @{ sub = 'x' } -Algorithm PS256 -Key $script:rsa).Signature
            $b = (New-Jwt -Payload @{ sub = 'x' } -Algorithm PS256 -Key $script:rsa).Signature
            $a | Should -Not -Be $b
        }

        It 'RS256 signatures are deterministic for the same input' {
            $a = (New-Jwt -Payload @{ sub = 'x' } -Algorithm RS256 -Key $script:rsa).Signature
            $b = (New-Jwt -Payload @{ sub = 'x' } -Algorithm RS256 -Key $script:rsa).Signature
            $a | Should -Be $b
        }
    }

    Context 'JWK Thumbprint (RFC 7638)' {
        It 'matches the RFC 7638 §3.1 reference vector' {
            $json = @'
{"keys":[{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}]}
'@
            $jwk = (ConvertFrom-JwtKeySet -Json $json).keys[0]
            Get-JwtKeyThumbprint -Key $jwk | Should -Be 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'
        }

        It 'computes thumbprints for EC and oct kty' {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $ec = [System.Security.Cryptography.ECDsa]::Create(
                [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
            try {
                $rsaJwk = ConvertTo-JwtKey -Key $rsa
                $ecJwk = ConvertTo-JwtKey -Key $ec
                $octJwk = ConvertTo-JwtKey -Key ([byte[]](1..32))

                Get-JwtKeyThumbprint -Key $rsaJwk | Should -Match '^[A-Za-z0-9_-]{43}$'
                Get-JwtKeyThumbprint -Key $ecJwk | Should -Match '^[A-Za-z0-9_-]{43}$'
                Get-JwtKeyThumbprint -Key $octJwk | Should -Match '^[A-Za-z0-9_-]{43}$'
            } finally {
                $rsa.Dispose()
                $ec.Dispose()
            }
        }

        It 'supports SHA-384 and SHA-512 thumbprint variants' {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            try {
                $jwk = ConvertTo-JwtKey -Key $rsa
                Get-JwtKeyThumbprint -Key $jwk -HashAlgorithm SHA384 | Should -Match '^[A-Za-z0-9_-]{64}$'
                Get-JwtKeyThumbprint -Key $jwk -HashAlgorithm SHA512 | Should -Match '^[A-Za-z0-9_-]{86}$'
            } finally { $rsa.Dispose() }
        }

        It 'fails when a required field is missing' {
            $jwk = (ConvertFrom-JwtKeySet -Json '{"keys":[{"kty":"RSA","e":"AQAB"}]}').keys[0]
            { Get-JwtKeyThumbprint -Key $jwk } | Should -Throw '*missing*'
        }
    }

    Context 'JWK Set (RFC 7517 §5)' {
        BeforeAll {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $ec = [System.Security.Cryptography.ECDsa]::Create(
                [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
            $script:rsaForSet = $rsa
            $script:ecForSet = $ec
            $script:rsaJwk = ConvertTo-JwtKey -Key $rsa -KeyId 'rsa-1' -Algorithm RS256
            $script:ecJwk = ConvertTo-JwtKey -Key $ec -KeyId 'ec-1' -Algorithm ES256
        }

        AfterAll {
            $script:rsaForSet.Dispose()
            $script:ecForSet.Dispose()
        }

        It 'wraps multiple keys via ConvertTo-JwtKeySet' {
            $set = $script:rsaJwk, $script:ecJwk | ConvertTo-JwtKeySet
            $set.GetType().Name | Should -Be 'JwtKeySet'
            $set.keys.Count | Should -Be 2
        }

        It 'serializes to a JWKS JSON document with a "keys" array' {
            $set = $script:rsaJwk, $script:ecJwk | ConvertTo-JwtKeySet
            $json = $set.ToJson()
            $json | Should -Match '"keys":\['
            $json | Should -Match '"kid":"rsa-1"'
            $json | Should -Match '"kid":"ec-1"'
        }

        It 'round-trips through ConvertFrom-JwtKeySet' {
            $set = $script:rsaJwk, $script:ecJwk | ConvertTo-JwtKeySet
            $parsed = ConvertFrom-JwtKeySet -Json $set.ToJson()
            $parsed.keys.Count | Should -Be 2
            $parsed.keys[0].kid | Should -Be 'rsa-1'
            $parsed.keys[1].kid | Should -Be 'ec-1'
        }

        It 'rejects JWKS JSON missing the keys array' {
            { ConvertFrom-JwtKeySet -Json '{}' } | Should -Throw "*'keys'*"
        }

        It 'Get-JwtKeyFromSet returns the matching JwtKey by kid' {
            $set = $script:rsaJwk, $script:ecJwk | ConvertTo-JwtKeySet
            (Get-JwtKeyFromSet -KeySet $set -KeyId 'ec-1').crv | Should -Be 'P-256'
        }

        It 'Get-JwtKeyFromSet returns $null for an unknown kid' {
            $set = $script:rsaJwk, $script:ecJwk | ConvertTo-JwtKeySet
            Get-JwtKeyFromSet -KeySet $set -KeyId 'nope' | Should -BeNullOrEmpty
        }

        It '-ErrorIfMissing emits a non-terminating error for an unknown kid' {
            $set = $script:rsaJwk, $script:ecJwk | ConvertTo-JwtKeySet
            $err = $null
            Get-JwtKeyFromSet -KeySet $set -KeyId 'nope' -ErrorIfMissing -ErrorVariable err -ErrorAction SilentlyContinue
            $err.Count | Should -BeGreaterThan 0
        }

        It 'Test-Jwt verifies a token whose kid is resolved from a JWKS' {
            $set = $script:rsaJwk, $script:ecJwk | ConvertTo-JwtKeySet
            $jwt = New-Jwt -Payload @{ sub = 'app' } -Algorithm ES256 -Key $script:ecForSet -Header @{ kid = 'ec-1' }
            $kid = (Get-JwtHeader -Token $jwt).kid
            $resolved = Get-JwtKeyFromSet -KeySet $set -KeyId $kid
            Test-Jwt -Token $jwt -Key $resolved -RequireExpiration $false | Should -BeTrue
        }
    }

    Context 'Module manifest' {
        It 'declares PowerShell 7.6 as the minimum version' {
            $manifest = Import-PowerShellDataFile "$PSScriptRoot/../src/manifest.psd1"
            $manifest.PowerShellVersion | Should -Be '7.6'
            $manifest.CompatiblePSEditions | Should -Be @('Core')
        }
    }
}
