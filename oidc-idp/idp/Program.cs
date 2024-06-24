
using Excid.Security.Authorization;
using Excid.Security.Trust;
using Microsoft.AspNetCore.HttpOverrides;



var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<IJwtBearerAuthorizer, JwtBearerAuthorizer>();
builder.Services.AddSingleton<IIssuerTrustList, IssuerTrustListFromConfiguration>();

var app = builder.Build();



app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto
});

app.UseStaticFiles();

app.UseRouting();

app.MapControllerRoute(
	name: "well-known",
	pattern: ".well-known/{action}",
	defaults: new { controller = "WellKnown", action = "openid-credential-issuer" });

app.MapControllerRoute(
	name: "default",
	pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
