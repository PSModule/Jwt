#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'Encoding segment' {
    Context 'ConvertFrom-Base64UrlString' {
        It 'decodes base64url strings to UTF-8 text' {
            ConvertFrom-Base64UrlString 'SGVsbG8' | Should -Be 'Hello'
        }
    }

    Context 'ConvertTo-Base64UrlString' {
        It 'encodes UTF-8 strings into base64url' {
            ConvertTo-Base64UrlString 'Hello' | Should -Be 'SGVsbG8'
        }
    }
}
