using Microsoft.IdentityModel.Tokens;


namespace Excid.Security.Trust
{
    public interface IIssuerTrustList
    {
        public JsonWebKey? GetTrustedIssuer(string id);
    }
}
