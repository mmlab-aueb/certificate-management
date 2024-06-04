/*
 * RFC 7523 JWT Bearer Assertion
 */

using System;
using System.IdentityModel.Tokens.Jwt;

namespace Excid.Oauth2.Models
{
    public class JwtBearerAssertion
    {
        
        public string? Issuer { get; set; } = null;
        public string? Subject { get; set; } = null;
        public string? Audience { get; set; } = null;
        public long? Expire { get; set; } = null;
        public long? NotBefore { get; set; } = null;
        public long? IssuedAt { get; set; } = null;
        public string? Id { get; set; } = null;
        
        private JwtSecurityToken? assertion = null;

        public JwtBearerAssertion() { }

        public JwtBearerAssertion(string base64JwtBearerAssertion) 
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            assertion = tokenHandler.ReadJwtToken(base64JwtBearerAssertion);
            Issuer = assertion.Payload.GetValueOrDefault("iss") as string;
            Subject = assertion.Payload.GetValueOrDefault("sub") as string;
            Audience = assertion.Payload.GetValueOrDefault("aud") as string;
            Expire = assertion.Payload.GetValueOrDefault("exp") as long?;
            NotBefore = assertion.Payload.GetValueOrDefault("exp") as long?;
            IssuedAt = assertion.Payload.GetValueOrDefault("iat") as long?;
            Id = assertion.Payload.GetValueOrDefault("jti") as string;
        }
    }
}

