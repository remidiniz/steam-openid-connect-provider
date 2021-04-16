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
using Microsoft.AspNetCore.Authentication.Cookies;

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
            // This fixes old browsers behaviour: https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.Secure = CookieSecurePolicy.Always;
                options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
                options.OnAppendCookie = cookieContext => 
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
                options.OnDeleteCookie = cookieContext => 
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            });

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
                .AddProfileService<SteamProfileService>()
                .AddInMemoryClients(IdentityServerConfig.GetClients(
                    Configuration["OpenID:ClientID"],
                    Configuration["OpenID:ClientSecret"],
                    Configuration["OpenID:RedirectUri"],
                    Configuration["OpenID:PostLogoutRedirectUri"],
                    Configuration["OpenID:AllowedHost"]))
                .AddInMemoryPersistedGrants()
                .AddDeveloperSigningCredential(true)
                .AddInMemoryIdentityResources(IdentityServerConfig.GetIdentityResources())
                .AddInMemoryApiResources(IdentityServerConfig.GetApiResources());

            // services.AddIdentityServer(options =>
            //     {
            //         options.UserInteraction.LoginUrl = "/ExternalLogin";
            //     })
            //     .AddTemporarySigningCredential()
            //     .AddInMemoryIdentityResources(IdentityServerConfig.GetIdentityResources())
            //     // .AddInMemoryApiResources(IdentityServerConfig.GetApiResources())
            //     .AddInMemoryClients(IdentityServerConfig.GetClients(
            //         Configuration["OpenID:ClientID"],
            //         Configuration["OpenID:ClientSecret"],
            //         Configuration["OpenID:RedirectUri"],
            //         Configuration["OpenID:PostLogoutRedirectUri"],
            //         Configuration["OpenID:AllowedHost"]))
            //     .AddAspNetIdentity<ApplicationUser>()
            //     .AddProfileService<ProfileService>();

            // Required for custom claims in our token using our custom IProfileService
            // services.AddTransient<IProfileService, SteamProfileService>(); //TODO: remove because we shouldn't use it ? https://stackoverflow.com/questions/44761058/how-to-add-custom-claims-to-access-token-in-identityserver4/44822276#44822276

            services.AddScoped<IProfileService, SteamProfileService>(); // TODO: remove if Useless ?!
            services.AddHttpClient<IProfileService, SteamProfileService>();

            services.AddAuthentication()
            .AddCookie(options =>
            {
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.IsEssential = true;
            })
            .AddSteam(options =>
            {
                options.ApplicationKey = Configuration["Authentication:Steam:ApplicationKey"];
            });

            services.AddHealthChecks()
                .AddUrlGroup(new Uri("https://steamcommunity.com/openid"), "Steam");
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            var forwardOptions = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
                RequireHeaderSymmetry = false
            };
            forwardOptions.KnownNetworks.Clear();
            forwardOptions.KnownProxies.Clear();
            app.UseForwardedHeaders(forwardOptions);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // Add this before any other middleware that might write cookies
            app.UseCookiePolicy(new CookiePolicyOptions
            {
                Secure = CookieSecurePolicy.Always,
                MinimumSameSitePolicy = SameSiteMode.Unspecified,
                OnAppendCookie = cookieContext => 
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions),
                OnDeleteCookie = cookieContext => 
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions)
            });

            // This will write cookies, so make sure it's after the cookie policy
            app.UseAuthentication();
            
            app.Use(async (ctx, next) =>
            {
                if (!string.IsNullOrEmpty(Configuration["Hosting:PublicOrigin"]))
                {
                    ctx.SetIdentityServerOrigin(Configuration["Hosting:PublicOrigin"]);
                }

                // https://stackoverflow.com/a/45312462/3254208
                if (!string.IsNullOrEmpty(Configuration["Hosting:PathBase"]))
                {
                    ctx.Request.PathBase = Configuration["Hosting:PathBase"];
                }

                await next();
            });

            app.UseRouting();
            app.UseIdentityServer();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapHealthChecks("/health");
            });
        }

        private void CheckSameSite(HttpContext httpContext, CookieOptions options)
        {
            if (options.SameSite == SameSiteMode.None)
            {
                var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
                // If UserAgent doesn’t support new behavior 
                if(DisallowsSameSiteNone(userAgent)) {
                    // options.SameSite = (SameSiteMode)(-1);
                    options.SameSite = SameSiteMode.Unspecified;
                }
            }
        }

        private bool DisallowsSameSiteNone(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
            {
                return false;
            }

            // Cover all iOS based browsers here. This includes:
            // - Safari on iOS 12 for iPhone, iPod Touch, iPad
            // - WkWebview on iOS 12 for iPhone, iPod Touch, iPad
            // - Chrome on iOS 12 for iPhone, iPod Touch, iPad
            // All of which are broken by SameSite=None, because they use the iOS networking stack
            if (userAgent.Contains("CPU iPhone OS 12") || userAgent.Contains("iPad; CPU OS 12"))
            {
                return true;
            }

            // Cover Mac OS X based browsers that use the Mac OS networking stack. This includes:
            // - Safari on Mac OS X.
            // This does not include:
            // - Chrome on Mac OS X
            // Because they do not use the Mac OS networking stack.
            if (userAgent.Contains("Macintosh; Intel Mac OS X 10_14") && 
                userAgent.Contains("Version/") && userAgent.Contains("Safari"))
            {
                return true;
            }

            // Cover Chrome 50-69, because some versions are broken by SameSite=None, 
            // and none in this range require it.
            // Note: this covers some pre-Chromium Edge versions, 
            // but pre-Chromium Edge does not require SameSite=None.
            if (userAgent.Contains("Chrome/5") || userAgent.Contains("Chrome/6"))
            {
                return true;
            }

            return false;
        }
    }
}
