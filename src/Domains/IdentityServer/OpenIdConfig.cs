using System;
using System.Collections.Generic;

namespace SteamOpenIdConnectProvider.Domains.IdentityServer;

public class OpenIdConfig
{
    public static readonly string Key = "OpenID";

    public string ClientID { get; set; }
    public string ClientSecret { get; set; }
    public string RedirectUri { get; set; }
    public string PostLogoutRedirectUri { get; set; }
    public string ClientName { get; set; } = "Proxy Client";
    public string IssuerUri { get; set; }
    public IEnumerable<string> RedirectUris => (RedirectUri ?? string.Empty).Split(
        new[] { ',', ';' },
        StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

    public IEnumerable<string> PostLogoutRedirectUris => (PostLogoutRedirectUri ?? string.Empty).Split(
        new[] { ',', ';' },
        StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
}
