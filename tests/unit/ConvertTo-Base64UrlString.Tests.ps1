#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'ConvertTo-Base64UrlString' {
    It 'encodes UTF-8 strings into base64url' {
        ConvertTo-Base64UrlString 'Hello' | Should -Be 'SGVsbG8'
    }
}

