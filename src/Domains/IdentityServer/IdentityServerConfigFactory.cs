﻿using System.Collections.Generic;
using System.Linq;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using SteamOpenIdConnectProvider.Domains.IdentityServer;

namespace SteamOpenIdConnectProvider.Models.IdentityServer;

public static class IdentityServerConfigFactory
{
    public static IEnumerable<Client> GetClients(OpenIdConfig config)
    {
        var client = new Client
        {
            ClientId = config.ClientID,
            ClientName = config.ClientName,
            AllowedGrantTypes = GrantTypes.Code,
            RequireConsent = false,
            ClientSecrets =
            {
                new Secret(config.ClientSecret.Sha256())
            },
            AlwaysSendClientClaims = true,
            AlwaysIncludeUserClaimsInIdToken = true,

            // where to redirect to after login
            RedirectUris = config.RedirectUris.ToArray(),

            // where to redirect to after logout
            PostLogoutRedirectUris = config.PostLogoutRedirectUris.ToArray(),

            RequirePkce = false,
            AllowedScopes = new List<string>
            {
                IdentityServerConstants.StandardScopes.OpenId,
                IdentityServerConstants.StandardScopes.Profile,
            }
        };
        yield return client;
    }

    public static IEnumerable<IdentityResource> GetIdentityResources()
    {
        return new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile()
        };
    }
}
