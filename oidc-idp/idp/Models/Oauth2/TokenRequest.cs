using Microsoft.AspNetCore.Mvc;

namespace Excid.Oauth2.Models
{
    public class TokenRequest
    {
        [BindProperty(Name = "grant_type")]
        public string? GrantType { get; set; } = null;

        [BindProperty(Name = "scope")]
        public string? Scope { get; set; } = null;

        [BindProperty(Name = "client_id")]
        public string? ClientId { get; set; } = null;

        //RFC 7521
        [BindProperty(Name = "client_assertion_type")]
        public string? ClientAssertion_type { get; set; } = null;

        [BindProperty(Name = "client_assertion")]
        public string? ClientAssertion { get; set; } = null;

        [BindProperty(Name = "assertion")]
        public string? Assertion { get; set; } = null;

    }
}
