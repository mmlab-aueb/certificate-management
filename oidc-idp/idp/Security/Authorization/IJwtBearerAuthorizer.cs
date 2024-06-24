using Excid.Oauth2.Models;
using Excid.Security.Authorization;

namespace Excid.Security.Authorization
{
    public interface IJwtBearerAuthorizer
    {
        public JwtBearerAuthorizationResult Authorize(JwtBearerAssertion assertion);
    }
}
