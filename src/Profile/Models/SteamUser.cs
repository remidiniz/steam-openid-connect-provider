using Microsoft.AspNetCore.Identity;

namespace SteamOpenIdConnectProvider
{
    public class SteamUser : IdentityUser
    {
        // public override string Id { get; set; }
        // public override string UserName { get; set; }
        public string Picture { get; set; }
    }
}