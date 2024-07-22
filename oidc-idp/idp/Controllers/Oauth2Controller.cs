using Excid.Oauth2.Models;
using Excid.Security.Authorization;
using Excid.Staas.Security;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace Excid.Oauth2.Controllers
{
    [ApiController]
    [Route("[controller]/[action]")]
    public class Oauth2Controller : ControllerBase
    {
        private readonly ILogger _logger;
        private readonly IJwtBearerAuthorizer _jwtBearerAuthorizer;
        private readonly IConfiguration _configuration;
        private readonly IJwtSigner _jwtSigner;

        public Oauth2Controller( ILogger<Oauth2Controller> logger, IJwtBearerAuthorizer jwtBearerAuthorizer, IConfiguration configuration, IJwtSigner jwtSigner)
        {
            _logger = logger;
            _configuration = configuration;
            _jwtBearerAuthorizer = jwtBearerAuthorizer;
            _jwtSigner = jwtSigner;
        }
        [HttpGet]
        public IActionResult Index()
        {
            return Ok();
        }

        [HttpPost]
        public IActionResult Token([FromForm] TokenRequest? request)
        {
            if(request == null)
            {
                return BadRequest(new { error = "invalid_request" });
            }
            if (request.GrantType == null) 
            {
                return BadRequest(new { error = "invalid_request" });
            }
            if (request.GrantType == "urn:ietf:params:oauth:grant-type:jwt-bearer") //RFC 7523
            {
                if (request.Assertion == null)
                {
                    return BadRequest(new { error = "invalid_grant" });
                }
                JwtBearerAssertion assertion;
                try
                {
                    assertion = new JwtBearerAssertion(request.Assertion);
                    var authorizationResult = _jwtBearerAuthorizer.Authorize(assertion);
                    if (authorizationResult.Result == false) 
                    {
                        _logger.LogInformation("Oauth2Contoller, error validating authorization " + authorizationResult.ErrorDesciption);
                        return BadRequest(new { error = "invalid_grant" });
                    }

                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Oauth2Contoller, invalid assertion received " + ex.ToString());
                    return BadRequest(new { error = "invalid_grant" });
                }
                _logger.LogInformation(JsonSerializer.Serialize(assertion));
                /*
			 * Prepare OIDC token
			 */
            var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var exp = DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds();
            var iss = _configuration.GetValue<string>("IdP:iss");
            var jwtpayload = new JwtPayload()
                {
                    { "iat", iat },
                    { "exp", exp },
                    { "iss", iss ?? ""},
                    {"aud", "sigstore" },
                    {"email_verified", true },
                    {"email", assertion.Subject }

                };
             var token = _jwtSigner.GetSignedJWT(jwtpayload);
             return Ok(JsonSerializer.Serialize( new { id_token = token, token_type = "Bearer", expires_in = 3600 }));
            }

            return BadRequest(new { error = "invalid_request" });
        }


    }
}
