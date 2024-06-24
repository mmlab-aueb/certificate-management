namespace Excid.Security.Authorization
{
    public class JwtBearerAuthorizationResult
    {
        public bool Result { get; set; }
        public string ErrorDesciption { get; set; } = string.Empty;
    }
}
