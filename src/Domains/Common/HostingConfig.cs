namespace SteamOpenIdConnectProvider.Domains.Common;

public class HostingConfig
{
    public static readonly string Key = "Hosting";

    public string BasePath { get; set; }

    public string PublicOrigin { get; set; }
}
