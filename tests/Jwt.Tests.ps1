[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Required for Pester tests'
)]
[CmdletBinding()]
param()

Describe 'Data-driven tests' {
    $testCases = . "$PSScriptRoot/Data/TestCases.ps1"

    Context '<Name>' -ForEach $testCases {
        It 'ConvertTo-Base64UrlString - encodes the header as base64url' {
            ConvertTo-Base64UrlString $Header | Should -Be $HeaderEncoded
        }

        It 'ConvertFrom-Base64UrlString - decodes the header from base64url' {
            ConvertFrom-Base64UrlString $HeaderEncoded | Should -Be $Header
        }

        It 'ConvertTo-Base64UrlString - encodes the payload as base64url' {
            ConvertTo-Base64UrlString $Payload | Should -Be $PayloadEncoded
        }

        It 'ConvertFrom-Base64UrlString - decodes the payload from base64url' {
            ConvertFrom-Base64UrlString $PayloadEncoded | Should -Be $Payload
        }

        It 'Get-JwtHeader - extracts the header' {
            Get-JwtHeader $ExtractionToken | Should -Be $Header
        }

        It 'Get-JwtPayload - extracts the payload' {
            Get-JwtPayload $ExtractionToken | Should -Be $Payload
        }

        It 'New-Jwt/Test-Jwt - creates and validates the token' {
            $jwt = New-Jwt -Header $Header -PayloadJson $Payload -Secret $Secret

            $parts = $jwt.Split('.')
            $parts.Count | Should -Be 3
            if ($null -ne $ExpectedToken) {
                $jwt | Should -Be $ExpectedToken
            }
            Get-JwtHeader $jwt | Should -Be $Header
            Get-JwtPayload $jwt | Should -Be $Payload
            Test-Jwt -jwt $jwt -Secret $Secret | Should -BeTrue
        }

        It 'Test-Jwt - fails validation for a tampered token' {
            $jwt = New-Jwt -Header $Header -PayloadJson $Payload -Secret $Secret
            $parts = $jwt.Split('.')
            $parts[1] = ConvertTo-Base64UrlString $TamperedPayload

            Test-Jwt -jwt ($parts -join '.') -Secret $Secret | Should -BeFalse
        }

        It 'New-Jwt - requires a secret' {
            { New-Jwt -Header $Header -PayloadJson $Payload } | Should -Throw '*HS256 requires -Secret parameter*'
        }
    }

    Context 'General behavior' {
        It 'ConvertFrom-Base64UrlString - returns bytes when requested' {
            $bytes = ConvertFrom-Base64UrlString 'SGVsbG8' -AsByteArray

            [System.Text.Encoding]::UTF8.GetString($bytes) | Should -Be 'Hello'
        }

        It 'ConvertFrom-Base64UrlString - rejects invalid base64url length' {
            { ConvertFrom-Base64UrlString 'A' } | Should -Throw '*Invalid base64url string length*'
        }

        It 'ConvertTo-Base64UrlString - throws for unsupported input types' {
            { ConvertTo-Base64UrlString ([pscustomobject]@{ Value = 'invalid' }) } | Should -Throw '*requires string or byte array input*'
        }

        It 'New-Jwt/Test-Jwt - creates an unsigned token when using the none algorithm' {
            $jwt = New-Jwt -Header '{"alg":"none","typ":"JWT"}' -PayloadJson '{"sub":"joe","role":"admin"}'

            $jwt | Should -Match '\.$'
            Test-Jwt -jwt $jwt | Should -BeTrue
        }

        It 'New-Jwt - requires the payload to be valid JSON' {
            { New-Jwt -Header '{"alg":"HS256","typ":"JWT"}' -PayloadJson 'not-json' -Secret 'super-secret' } | Should -Throw '*payload is not JSON*'
        }

        It 'Get-JwtHeader - requires exactly three JWT segments' {
            { Get-JwtHeader 'header.payload' } | Should -Throw '*JWT must have exactly 3 segments*'
        }

        It 'Get-JwtPayload - requires a payload segment' {
            { Get-JwtPayload 'header..signature' } | Should -Throw '*JWT payload segment is missing*'
        }

        It 'Test-Jwt - requires exactly three JWT segments' {
            { Test-Jwt 'header.payload' } | Should -Throw '*JWT must have exactly 3 segments*'
        }

        It 'Test-Jwt - rejects unsigned tokens without a third segment' {
            $header = ConvertTo-Base64UrlString '{"alg":"none","typ":"JWT"}'
            $payload = ConvertTo-Base64UrlString '{"sub":"joe","role":"admin"}'

            { Test-Jwt "$header.$payload" } | Should -Throw '*JWT must have exactly 3 segments*'
        }

        It 'Test-Jwt - returns false for an invalid HS256 signature segment' {
            $jwt = New-Jwt -Header '{"alg":"HS256","typ":"JWT"}' -PayloadJson '{"sub":"joe","role":"admin"}' -Secret 'super-secret'
            $parts = $jwt.Split('.')
            $parts[2] = 'A'

            Test-Jwt -jwt ($parts -join '.') -Secret 'super-secret' | Should -BeFalse
        }

        It 'Verbose output does not include JWT or payload values' {
            $payload = '{"sub":"joe","role":"admin"}'
            $jwt = New-Jwt -Header '{"alg":"HS256","typ":"JWT"}' -PayloadJson $payload -Secret 'super-secret'

            $newJwtVerbose = & { New-Jwt -Header '{"alg":"HS256","typ":"JWT"}' -PayloadJson $payload -Secret 'super-secret' -Verbose } 4>&1 |
                Where-Object { $_.GetType().Name -eq 'VerboseRecord' } |
                Out-String
            $getHeaderVerbose = & { Get-JwtHeader $jwt -Verbose } 4>&1 |
                Where-Object { $_.GetType().Name -eq 'VerboseRecord' } |
                Out-String
            $getPayloadVerbose = & { Get-JwtPayload $jwt -Verbose } 4>&1 |
                Where-Object { $_.GetType().Name -eq 'VerboseRecord' } |
                Out-String
            $testJwtVerbose = & { Test-Jwt -jwt $jwt -Secret 'super-secret' -Verbose } 4>&1 |
                Where-Object { $_.GetType().Name -eq 'VerboseRecord' } |
                Out-String

            $newJwtVerbose | Should -Not -Match ([regex]::Escape($payload))
            $getHeaderVerbose | Should -Not -Match ([regex]::Escape($jwt))
            $getPayloadVerbose | Should -Not -Match ([regex]::Escape($jwt))
            $testJwtVerbose | Should -Not -Match ([regex]::Escape($jwt))
        }
    }
}
