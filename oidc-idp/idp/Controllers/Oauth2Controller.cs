using Excid.Oauth2.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace Excid.Oauth2.Controllers
{
    [ApiController]
    [Route("[controller]/[action]")]
    public class Oauth2Controller : ControllerBase
    {
        private readonly ILogger _logger;

        public Oauth2Controller( ILogger<Oauth2Controller> logger)
        {
            _logger = logger;
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
                }
                catch (Exception ex)
                {
                    return BadRequest(new { error = "invalid_grant" });
                }
                _logger.LogInformation(JsonSerializer.Serialize(assertion));
                return Ok();
            }

            return BadRequest(new { error = "invalid_request" });
        }


    }
}
