using System;
using System.Net.Http;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using IdentityServer4.Services;
using Microsoft.AspNetCore.HttpOverrides;
using SteamOpenIdConnectProvider.Database;
using SteamOpenIdConnectProvider.Profile;

namespace SteamOpenIdConnectProvider
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers()
                .AddNewtonsoftJson()
                .SetCompatibilityVersion(CompatibilityVersion.Version_3_0);

            services.AddSingleton(Configuration);
            services.AddDbContext<AppInMemoryDbContext>(options =>
                options.UseInMemoryDatabase("default"));

            services.AddIdentity<IdentityUser, IdentityRole>(options =>
                {
                    options.User.AllowedUserNameCharacters = null;
                })
                .AddEntityFrameworkStores<AppInMemoryDbContext>()
                .AddDefaultTokenProviders();

            services.AddIdentityServer(options =>
                {
                    options.UserInteraction.LoginUrl = "/ExternalLogin";
                })
                .AddAspNetIdentity<IdentityUser>()
                .AddInMemoryClients(IdentityServerConfig.GetClients(
                    Configuration["OpenID:ClientID"],
                    Configuration["OpenID:ClientSecret"],
                    Configuration["OpenID:RedirectUri"],
                    Configuration["OpenID:PostLogoutRedirectUri"],
                    Configuration["OpenID:AllowedHost"]))
                .AddInMemoryPersistedGrants()
                .AddDeveloperSigningCredential(true)
                .AddInMemoryIdentityResources(IdentityServerConfig.GetIdentityResources());

            services.AddHttpClient<IProfileService, SteamProfileService>();

            services.AddAuthentication()
            // TODO: remove AddCookie if confirmed useless
                // .AddCookie(options =>
                // {
                //     options.Cookie.SameSite = SameSiteMode.Strict;
                //     options.Cookie.IsEssential = true;
                // })
                // .AddCookie(options =>
                // {
                //     options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                //     options.Cookie.SameSite = SameSiteMode.None;
                // })
                // .AddCookie(options =>
                // {
                //     options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                //     options.Cookie.SameSite = SameSiteMode.Lax;
                // })
                .AddSteam(options =>
                {
                    options.ApplicationKey = Configuration["Authentication:Steam:ApplicationKey"];
                });

            services.AddHealthChecks()
                .AddUrlGroup(new Uri("https://steamcommunity.com/openid"), "Steam");
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // Fix the Cookie SameSitePolicy
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();

                app.UseCookiePolicy(new CookiePolicyOptions
                {
                    MinimumSameSitePolicy = SameSiteMode.None,
                    Secure = CookieSecurePolicy.Always
                });
            } else {
                app.UseCookiePolicy(new CookiePolicyOptions
                {
                    MinimumSameSitePolicy = SameSiteMode.Lax,
                    Secure = CookieSecurePolicy.Always
                });
            }

            if (!string.IsNullOrEmpty(Configuration["Hosting:PathBase"]))
            {
                app.UsePathBase(Configuration["Hosting:PathBase"]);
            }
            
            app.Use(async (ctx, next) =>
            {
                var origin = Configuration["Hosting:PublicOrigin"];
                if (!string.IsNullOrEmpty(origin))
                {
                    ctx.SetIdentityServerOrigin(origin);
                }

                await next();
            });

            var forwardOptions = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
                RequireHeaderSymmetry = false
            };

            forwardOptions.KnownNetworks.Clear();
            forwardOptions.KnownProxies.Clear();

            app.UseForwardedHeaders(forwardOptions);
            app.UseRouting();
            app.UseIdentityServer();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapHealthChecks("/health");
            });
        }
    }
}
