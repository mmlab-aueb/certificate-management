using Excid.Security.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace Excid.Security.Trust
{
    public class IssuerTrustListFromConfiguration: IIssuerTrustList
    {
        private readonly ILogger<JwtBearerAuthorizer> _logger;
        private readonly IConfiguration _configuration;
        private Dictionary<string, JsonWebKey> _trustedIssuers;

        public IssuerTrustListFromConfiguration(ILogger<JwtBearerAuthorizer> logger, IConfiguration configuration)
        {
            _configuration = configuration;
            _logger = logger;
            _trustedIssuers = [];
            try
            {
                var issuers = _configuration.GetSection("TrustedIssuers").Get<List<TrustListEntry>>();
                if (issuers == null)
                {
                    return;
                }
                foreach ( var item in issuers)
                {
                    _logger.LogInformation("Will parse:" + item.Id + " " + item.Jwk);
                    _trustedIssuers[item.Id] = new JsonWebKey(item.Jwk);
                }

            } catch (Exception ex){
                _logger.LogError("IssuerTrustListFromConfiguration, cannot read configuration " + ex.ToString());
            }
        }

        public JsonWebKey? GetTrustedIssuer(string id)
        {
            return _trustedIssuers.GetValueOrDefault(id);
        }
    }

    public class TrustListEntry
    {
        public string Id { get; set; } = string.Empty;
        public string Jwk { get; set; }=string.Empty;
    }
}
