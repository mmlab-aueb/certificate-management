import time
import json
import requests
from jwcrypto import jwk, jwt


'''
This key has been generated using the following commands
key = jwk.JWK.generate(kty='EC', crv='P-256')
key.export()

Note that it includes the private key as well
'''

json_key = json.dumps({
    "crv":"P-256",
    "d":"TvKuAqV1y1pTlWhJ_BG9WZZvnu1n0bonuleoZDtT89k",
    "kty":"EC","x":"3qmoY1Bs0eJ319TLku5ofe7q2guicdFSIu22miBLXHY",
    "y":"gRzDzzvTGuyJp7ypFWuboC21KhsxpcpQMo9IcXSt23E"
})

jwk_key = jwk.JWK.from_json(json_key)

# Generate an RFC 7523 assertion
jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "jwk":  jwk_key.export_public(as_dict=True)
        }
jwt_claims={
    "iss":"http://localhost",
    "sub":"http://localhost",
    "aud":"http://localhost:6001",
    "exp": int(time.time()) + 600 #expire in 10 minutes
}

assertion = jwt.JWT(header=jwt_header, claims=jwt_claims)
assertion.make_signed_token( jwk_key)
print (assertion.serialize())

# Generate access token request
data={
    "grant_type":"urn:ietf:params:oauth:grant-type:jwt-bearer",
    "assertion":assertion.serialize()
}

headers={
    "Content-Type":"application/x-www-form-urlencoded"
}

print(data)
token_url = "http://localhost:6001/oauth2/Token"

response = requests.post(token_url, headers = headers, data = data)
print (response.status_code)