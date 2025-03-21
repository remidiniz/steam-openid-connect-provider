using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SteamOpenIdConnectProvider.Profile.Models;

namespace SteamOpenIdConnectProvider.Database
{
    // This is completely in-memory, we do not need a persistent store.
    public class AppInMemoryDbContext : IdentityDbContext<SteamUser>
    {
        public AppInMemoryDbContext(DbContextOptions<AppInMemoryDbContext> options)
            : base(options)
        {
        }
    }
}
