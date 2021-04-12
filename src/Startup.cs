﻿using System;
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
// // using Microsoft.Owin.Security.OpenIdConnect;
// using Microsoft.AspNetCore.Authentication.OpenIdConnect;
// using Microsoft.Owin.Host.SystemWeb;

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

            // services.Configure<CookiePolicyOptions>(options =>
            // {
            //     options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
            //     options.OnAppendCookie = cookieContext => 
            //         CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            //     options.OnDeleteCookie = cookieContext => 
            //         CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            // });

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
            .AddCookie(options =>
            {
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.None;
            })
            // .AddCookie(new SameSiteCookieManager(new SystemWebCookieManager()))
            // .AddOpenIdConnect(
            //     // new OpenIdConnectAuthenticationOptions
            //     new OpenIdConnectOptions
            //     {
            //     // … Your preexisting options … 
            //     CookieManager = new SameSiteCookieManager(new SystemWebCookieManager())
            // })
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

                // app.UseCookiePolicy(new CookiePolicyOptions
                // {
                //     MinimumSameSitePolicy = SameSiteMode.None,
                //     Secure = CookieSecurePolicy.Always
                // });
            } /* else {
                app.UseCookiePolicy(new CookiePolicyOptions
                {
                    MinimumSameSitePolicy = SameSiteMode.Lax,
                    Secure = CookieSecurePolicy.Always
                });
            } */

            // app.UseCookiePolicy();
            // app.UseOpenIdConnectAuthentication(
            //     new OpenIdConnectAuthenticationOptions
            //     {
            //     // … Your preexisting options … 
            //     CookieManager = new SameSiteCookieManager(new SystemWebCookieManager())
            // });

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

            // Fix SameSite: https://stackoverflow.com/a/51671538/3254208
            app.UseCookiePolicy(new CookiePolicyOptions
            {
                MinimumSameSitePolicy = SameSiteMode.None,
                Secure = CookieSecurePolicy.Always
            });
        }

        // private void CheckSameSite(HttpContext httpContext, CookieOptions options)
        // {
        //     if (options.SameSite == SameSiteMode.None)
        //     {
        //         var userAgent = httpContext.Request.Headers["User-Agent"].ToString();

        //         // If UserAgent doesn’t support new behavior 
        //         if(SameSiteCookieManager.DisallowsSameSiteNone(userAgent)) {
        //             // options.SameSite = (SameSiteMode)(-1);
        //             options.SameSite = SameSiteMode.Unspecified;
        //         }
        //     }
        // }

    }
}
