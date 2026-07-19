# Token commands

Public commands for JWT lifecycle operations:

- creating signed and unsigned tokens
- parsing compact JWT strings into typed objects
- inspecting token header, payload, and claims
- validating signature and registered claims

Validation path is parameter-set driven:

- `Test-Jwt -Token <jwt> -Key <key>` for signed algorithms
- `Test-Jwt -Token <jwt> -AllowUnsigned` for `alg = none`
