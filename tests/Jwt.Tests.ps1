[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Required for Pester tests'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'Tests construct in-memory key material'
)]
[CmdletBinding()]
param()

Describe 'Jwt' {
    BeforeAll {
        $script:rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $script:privatePem = $script:rsa.ExportRSAPrivateKeyPem()
    }

    AfterAll {
        if ($script:rsa) { $script:rsa.Dispose() }
    }

    Context 'JwtBase64Url' {
        It 'strips padding and replaces +/ with -_' {
            $encoded = [JwtBase64Url]::ConvertToBase64UrlFormat('ab+/cd==')
            $encoded | Should -Be 'ab-_cd'
        }

        It 'encodes a hashtable as URL-safe Base64 JSON' {
            $encoded = [JwtBase64Url]::Encode(@{ a = 1 })
            $encoded | Should -Be 'eyJhIjoxfQ'
        }

        It 'encodes a string as URL-safe Base64 UTF-8' {
            [JwtBase64Url]::Encode('hi') | Should -Be 'aGk'
        }
    }

    Context 'Jwt class' {
        It 'ToString() returns header.payload.signature' {
            $h = [JwtHeader]::new(@{ alg = 'RS256'; typ = 'JWT' })
            $p = [JwtPayload]::new(@{ iss = 'tester' })
            $jwt = [Jwt]::new($h, $p, 'sig')
            $jwt.ToString() | Should -Match '^[^.]+\.[^.]+\.sig$'
        }

        It 'preserves header field order (alg, typ, kid)' {
            $h = [JwtHeader]::new(@{ alg = 'RS256'; kid = 'k1' })
            $ordered = $h.ToOrderedDictionary()
            $keys = @($ordered.Keys)
            $keys[0] | Should -Be 'alg'
            $keys[1] | Should -Be 'typ'
            $keys[2] | Should -Be 'kid'
        }
    }

    Context 'New-Jwt with local RSA' {
        It 'returns a [Jwt] object' {
            $jwt = New-Jwt -Payload @{ iss = 'tester' } -PrivateKey $script:privatePem
            $jwt | Should -BeOfType [Jwt]
        }

        It 'produces a token with three Base64URL segments' {
            $jwt = New-Jwt -Payload @{ iss = 'tester' } -PrivateKey $script:privatePem
            $parts = $jwt.ToString().Split('.')
            $parts.Count | Should -Be 3
            $parts | ForEach-Object { $_ | Should -Not -BeNullOrEmpty }
        }

        It 'produces an RS256 signature that verifies with the public key' {
            $jwt = New-Jwt -Payload @{ iss = 'tester'; iat = 1700000000 } -PrivateKey $script:privatePem
            $parts = $jwt.ToString().Split('.')
            $signingInput = "$($parts[0]).$($parts[1])"

            $sigSegment = $parts[2].Replace('-', '+').Replace('_', '/')
            $padding = (4 - ($sigSegment.Length % 4)) % 4
            $sigBytes = [System.Convert]::FromBase64String($sigSegment + ('=' * $padding))

            $verified = $script:rsa.VerifyData(
                [System.Text.Encoding]::UTF8.GetBytes($signingInput),
                $sigBytes,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $verified | Should -BeTrue
        }

        It 'merges custom header fields and keeps alg from -Algorithm' {
            $jwt = New-Jwt -Header @{ kid = 'key-1' } -Payload @{ iss = 'tester' } -PrivateKey $script:privatePem
            $jwt.Header.kid | Should -Be 'key-1'
            $jwt.Header.alg | Should -Be 'RS256'
        }

        It 'accepts a [securestring] private key' {
            $secure = ConvertTo-SecureString -String $script:privatePem -AsPlainText -Force
            $jwt = New-Jwt -Payload @{ iss = 'tester' } -PrivateKey $secure
            $jwt | Should -BeOfType [Jwt]
        }

        It 'recognizes registered claims on the payload' {
            $jwt = New-Jwt -Payload @{ iss = 'tester'; sub = 'subj'; exp = 1700003600; iat = 1700000000 } `
                -PrivateKey $script:privatePem
            $jwt.Payload.iss | Should -Be 'tester'
            $jwt.Payload.sub | Should -Be 'subj'
            $jwt.Payload.exp | Should -Be 1700003600
            $jwt.Payload.iat | Should -Be 1700000000
        }
    }
}
