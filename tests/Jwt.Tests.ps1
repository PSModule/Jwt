[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Required for Pester tests'
)]
[CmdletBinding()]
param()

Describe 'Data-driven tests' {
    BeforeAll {
        $script:ModuleManifest = Join-Path $PSScriptRoot '../src/JWT.psd1'
        Import-Module -Name $script:ModuleManifest -Force
    }

    AfterAll {
        Remove-Module -Name JWT -Force -ErrorAction SilentlyContinue
    }

    $testCases = . "$PSScriptRoot/Data/TestCases.ps1"

    Context 'Module metadata' {
        It 'publishes the maintained Jwt continuation metadata' {
            $manifest = Import-PowerShellDataFile -Path $script:ModuleManifest

            $manifest.ModuleVersion.ToString() | Should -Be '1.9.2'
            $manifest.RootModule | Should -Be 'JWT.psm1'
            $manifest.GUID | Should -Be 'd4592298-b1a3-4a7d-b6fc-2ac16cc0e722'
            $manifest.PrivateData.PSData.ProjectUri | Should -Be 'https://github.com/PSModule/Jwt'
            $manifest.PrivateData.PSData.LicenseUri | Should -Be 'https://github.com/PSModule/Jwt/blob/main/LICENSE'
        }

        It 'exports the current Jwt command surface' {
            $expectedFunctions = @(
                'ConvertFrom-Base64UrlString'
                'ConvertTo-Base64UrlString'
                'Get-JwtHeader'
                'Get-JwtPayload'
                'New-Jwt'
                'Test-Jwt'
            )
            $commands = Get-Command -Module JWT | Select-Object -ExpandProperty Name

            foreach ($function in $expectedFunctions) {
                $commands | Should -Contain $function
            }

            Get-Alias -Name 'Verify-JwtSignature' | Select-Object -ExpandProperty ReferencedCommand | Should -Be 'Test-Jwt'
        }
    }

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
    }
}
