# Steam OpenId Connect Provider

Steam OpenID 2.0 -> OpenID Connect Provider Proxy

## About

This server allows you to use Steam as an OpenID Connect Identity provider (OIDC IDP). This way you can use Steam logins in KeyCloak or any other OpenID Connect based authentication client.

FORK NOTES:

- ~~fixes `Hosting__PathBase`~~
- fixes `AllowedHost` ? (TODO: need to confirm this really needs a fix...)
- fixes the `anti-forgery` cookie SameSite error:
  - Solution: https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/
  - Additional infos:
    - https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers/issues/79#issuecomment-604977562
    - https://cookie-script.com/documentation/samesite-cookie-attribute-explained#:~:text=SameSite%20cookie%20attribute%20is%20used,depending%20on%20attribute%20and%20scenario.
    - https://auth0.com/docs/sessions/cookies/samesite-cookie-attribute-changes

## Setup

Add your Steam API Key as user-secrets like this:
`dotnet user-secrets set "Authentication:Steam:ApplicationKey" "MySteamApiKey"`

Alternatively you can set it up via environment variables:
`Authentication__Steam__ApplicationKey=MySteamApiKey`
(Keep in mind that this is easier but more insecure)

After that set up your redirect URI, ClientID and ClientSecret in the appsettings.json.

If you need to set up multiple redirect URIs, you can set them separated by a comma.
`OpenID__RedirectUri="http://localhost:8080/auth/realms/master/broker/steam/endpoint, http://localhost:8080/auth/realms/dev/broker/steam/endpoint"`

## OpenID Configuration

You can access Authorization and Token endpoint details in
`http://<Your Host>/.well-known/openid-configuration`

## Supported Scopes

The following scopes are supported: `openid`, `profile`.

If you use the `profile` scope, you get access to the `picture`, `given_name`, `website` and `nickname` claims too.

## HTTPS Support

This server does not support https connections. If you want to use https connections please use a reverse proxy like nginx.

## Running behind reverse proxies

Some reverse proxy setups might require additional configuration, like setting the path base or origin.

To set the origin, set `Hosting:PublicOrigin` in the appsettings.json or the `Hosting__PublicOrigin` environment variable to your desired origin. If not set, the origin name is inferred from the request.

Similary, you can use the `Hosting:PathBase` in the appsettings.json or the `Hosting__PathBase` environment variable to set the path base. If not set, it will default to "/".

## Health checks

This service contains a health check endpoint at `/health`. It checks if the Steam login servers are working.

## Docker

[A docker image](https://hub.docker.com/r/imperialplugins/steam-openid-connect-provider) is also available.

```
docker run -it \
    -e OpenID__RedirectUri=http://localhost:8080/auth/realms/master/broker/steam/endpoint \
    -e OpenID__ClientID=steamidp \
    -e OpenID__ClientSecret=mysecret \
    -e Authentication__Steam__ApplicationKey=MySteamApiKey \
    --restart unless-stopped \
    --name steamidp \
    imperialplugins/steam-openid-connect-provider
```

## License

[MIT](https://github.com/ImperialPlugins/steam-openid-connect-provider/blob/master/LICENSE)
