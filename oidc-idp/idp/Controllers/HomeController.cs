using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using Excid.Oidc.Models;

namespace idp.Controllers
{
	[AllowAnonymous]
	public class HomeController : Controller
	{
		private readonly ILogger<HomeController> _logger;
		private readonly IConfiguration _configuration;
		private readonly JsonWebKey _publicJWK;


        public HomeController(IConfiguration configuration, ILogger<HomeController> logger)
		{
			_logger = logger;
			_configuration = configuration;
			_publicJWK = new JsonWebKey();
            string privateKeyPem = _configuration.GetValue<string>("IdP:PrivateKeyPem") ?? "";
            string privateKeyPemPassord = _configuration.GetValue<string>("IdP:PrivateKeyPemPassord") ?? "";
            try
            {
                string pemKey = System.IO.File.ReadAllText(privateKeyPem);
                var signingecdsa = ECDsa.Create();
                signingecdsa.ImportFromEncryptedPem(new System.ReadOnlySpan<char>(pemKey.ToCharArray()), privateKeyPemPassord);
                _publicJWK = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(signingecdsa));
                _publicJWK.D = null;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in Homecontroller:" + ex.ToString());
            }
        }


		public IActionResult Jwks()
		{
            var JwkSet = new JwkSet();
			JwkSet.Keys.Add(_publicJWK);
			return Content(JsonSerializer.Serialize(JwkSet), "application/json");
		}

       



	}
}