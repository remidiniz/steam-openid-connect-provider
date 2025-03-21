using Microsoft.AspNetCore.Identity;

namespace SteamOpenIdConnectProvider.Profile.Models
{
    public class SteamUser : IdentityUser
    {
        public string Picture { get; set; }
    }
}