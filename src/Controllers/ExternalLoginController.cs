﻿using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SteamOpenIdConnectProvider.Profile.Models;

namespace SteamOpenIdConnectProvider.Controllers
{
    [AllowAnonymous]
    [Route("[action]")]
    public class ExternalLoginController : Controller
    {
        private readonly SignInManager<SteamUser> _signInManager;
        private readonly UserManager<SteamUser> _userManager;
        private readonly ILogger<ExternalLoginController> _logger;

        public ExternalLoginController(
            SignInManager<SteamUser> signInManager,
            UserManager<SteamUser> userManager,
            ILogger<ExternalLoginController> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }


        [HttpGet]
        public Task<IActionResult> ExternalLogin(string returnUrl = null)
        {
            const string provider = "Steam";

            var redirectUrl = Url.Action("ExternalLoginCallback", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Task.FromResult<IActionResult>(new ChallengeResult(provider, properties));
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            returnUrl ??= Url.Content("~/");
           
            if (remoteError != null)
            {
                throw new Exception($"Error from external provider: {remoteError}");
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                throw new Exception($"Error loading external login information.");
            }

            var externalLoginResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (externalLoginResult.Succeeded)
            {
                _logger.LogInformation("{Name} logged in with {LoginProvider} provider.", info.Principal.Identity.Name, info.LoginProvider);
                return LocalRedirect(returnUrl);
            }

            var userName = info.Principal.FindFirstValue(ClaimTypes.Name);
            var userId = info.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
            
            var user = new SteamUser { UserName = userName, Id = userId, Picture = "https://www.csgo-stat-track.com/img/luckso.jpg" };

            _userManager.UserValidators.Clear();

            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                result = await _userManager.AddLoginAsync(user, info);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                    return LocalRedirect(returnUrl);
                }
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return BadRequest();
        }
    }
}
