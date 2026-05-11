@(
    @{
        Name            = 'local HS256 token'
        Header          = '{"alg":"HS256","typ":"JWT"}'
        HeaderEncoded   = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        Payload         = '{"sub":"joe","role":"admin"}'
        PayloadEncoded  = 'eyJzdWIiOiJqb2UiLCJyb2xlIjoiYWRtaW4ifQ'
        Secret          = 'super-secret'
        ExtractionToken = @(
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            'eyJzdWIiOiJqb2UiLCJyb2xlIjoiYWRtaW4ifQ'
            'c2lnbmF0dXJl'
        ) -join '.'
        ExpectedToken   = $null
        TamperedPayload = '{"sub":"joe","role":"user"}'
    }
    @{
        Name            = 'current jwt.io default HS256 example'
        Header          = '{"alg":"HS256","typ":"JWT"}'
        HeaderEncoded   = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        Payload         = '{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}'
        PayloadEncoded  = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0'
        Secret          = 'a-string-secret-at-least-256-bits-long'
        ExtractionToken = @(
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0'
            'KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30'
        ) -join '.'
        ExpectedToken   = @(
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0'
            'KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30'
        ) -join '.'
        TamperedPayload = '{"sub":"1234567890","name":"John Doe","admin":false,"iat":1516239022}'
    }
)
