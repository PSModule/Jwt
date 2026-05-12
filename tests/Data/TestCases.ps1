@(
    @{
        Name           = 'jwt.io HS256 default sample'
        Algorithm      = 'HS256'
        Header         = [ordered]@{ alg = 'HS256'; typ = 'JWT' }
        Payload        = [ordered]@{ sub = '1234567890'; name = 'John Doe'; admin = $true; iat = 1516239022 }
        Secret         = 'a-string-secret-at-least-256-bits-long'
        EncodedHeader  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        EncodedPayload = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0'
        EncodedSig     = 'KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30'
    }
    @{
        Name           = 'minimal HS256 sub claim'
        Algorithm      = 'HS256'
        Header         = [ordered]@{ alg = 'HS256'; typ = 'JWT' }
        Payload        = [ordered]@{ sub = 'joe' }
        Secret         = 'super-secret'
        EncodedHeader  = $null
        EncodedPayload = $null
        EncodedSig     = $null
    }
)
