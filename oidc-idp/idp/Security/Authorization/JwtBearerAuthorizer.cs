using Excid.Oauth2.Models;
using Excid.Security.Trust;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;



namespace Excid.Security.Authorization
{
    public class JwtBearerAuthorizer: IJwtBearerAuthorizer
    {
        private readonly ILogger<JwtBearerAuthorizer> _logger;
        private readonly IConfiguration _configuration;
        private readonly IIssuerTrustList _issuerTrustList;

        public JwtBearerAuthorizer(ILogger<JwtBearerAuthorizer> logger, IConfiguration configuration, IIssuerTrustList issuerTrustList)
        {
            _configuration = configuration;
            _logger = logger;
            _issuerTrustList = issuerTrustList;
        }

        public JwtBearerAuthorizationResult Authorize(JwtBearerAssertion assertion) 
        {
            JsonWebKey? issuerCertificate = null;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (assertion.Issuer == null)
            {
                return new JwtBearerAuthorizationResult() { Result = false, ErrorDesciption = "Issuer validation fail" };
            }
            else
            {
                issuerCertificate = _issuerTrustList.GetTrustedIssuer(assertion.Issuer);
                if (issuerCertificate == null)
                {
                    return new JwtBearerAuthorizationResult() { Result = false, ErrorDesciption = "Issuer not found" };

                }
            }
            if (assertion.Subject == null) // check also for trusted subject
            {
                return new JwtBearerAuthorizationResult() { Result = false, ErrorDesciption = "Subject validation fail" };
            }
            if (assertion.Audience == null) // check also for valid audience
            {
                return new JwtBearerAuthorizationResult() { Result = false, ErrorDesciption = "Audience validation fail" };
            }
            if (assertion.Expire == null || assertion.Expire <now) 
            {
                return new JwtBearerAuthorizationResult() { Result = false, ErrorDesciption = "Expiration validation fail" };
            }
            if(assertion.NotBefore != null)
            {
                if (assertion.NotBefore < now)
                {
                    return new JwtBearerAuthorizationResult() { Result = false, ErrorDesciption = "Nbf validation fail" };
                }
            }
            if (assertion.IssuedAt != null)
            {
                if (assertion.IssuedAt > now)
                {
                    return new JwtBearerAuthorizationResult() { Result = false, ErrorDesciption = "Issued validation fail" };
                }
            }
            if (assertion.Id != null)
            {
                //check
            }
            
            var validationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = issuerCertificate,
                ValidateLifetime = false,
                ValidateAudience = false,
                ValidateIssuer = false
            };
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.ValidateToken(assertion.Base64JwtBearerAssertion, validationParameters, out _);
            }catch (Exception ex)
            {
                _logger.LogError("JwtBearerAuthorizer, cannot verify signature " + ex.ToString());
                return new JwtBearerAuthorizationResult() { Result = false, ErrorDesciption = "Assertion signature verification fail" };
            }
            return new JwtBearerAuthorizationResult() { Result = true };
        }

    }

    
}
