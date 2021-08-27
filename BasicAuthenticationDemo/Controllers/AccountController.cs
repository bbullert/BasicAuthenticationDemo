using BasicAuthenticationDemo.Models;
using BasicAuthenticationDemo.Services.Validation;
using DataAccess.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using NETCore.MailKit.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace BasicAuthenticationDemo.Controllers
{
    public class AccountController : Controller
    {
        private readonly ILogger<AccountController> logger;
        private readonly UserManager<AppUser> userManager;
        private readonly SignInManager<AppUser> signInManager;
        private readonly AppIdentityErrorDescriber appIdentityErrorDescriber;
        private readonly IEmailService emailService;

        public AccountController(
            ILogger<AccountController> logger,
            UserManager<AppUser> userManager,
            SignInManager<AppUser> signInManager,
            AppIdentityErrorDescriber appIdentityErrorDescriber,
            IEmailService emailService)
        {
            this.logger = logger;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.appIdentityErrorDescriber = appIdentityErrorDescriber;
            this.emailService = emailService;
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginAsync(LoginViewModel model)
        {
            if (!string.IsNullOrEmpty(model.UserName) &&
                !string.IsNullOrEmpty(model.Password))
            {
                var user = await userManager.FindByNameAsync(model.UserName) ??
                       await userManager.FindByEmailAsync(model.UserName);

                if (user != null)
                {
                    var result = await signInManager.PasswordSignInAsync(
                            user,
                            model.Password,
                            model.RememberMe,
                            false
                        );

                    if (result.Succeeded)
                    {
                        return RedirectToAction("Index", "Home");
                    }
                }
            }

            ModelState.AddModelError(string.Empty, appIdentityErrorDescriber.InvalidUserNameOrPassword().Description);

            return View(model);
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterAsync(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new AppUser
                {
                    UserName = model.UserName,
                    Email = model.Email
                };

                var result = await userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await SendEmailConfirmationAsync(user);

                    return RedirectToAction("Login");
                }
            }

            return View(model);
        }

        public async Task<IActionResult> LogoutAsync()
        {
            await signInManager.SignOutAsync();

            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> ValidateUserNameAsync(string username)
        {
            var validators = userManager.UserValidators;

            foreach (var validator in validators)
            {
                var user = new AppUser { UserName = username };
                var result = await validator.ValidateAsync(userManager, user);

                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        if (error.Code.ToLower().Contains(nameof(username)))
                        {
                            ModelState.AddModelError(nameof(username), error.Description);
                        }
                    }
                }
            }

            var errors = ModelState.Values.SelectMany(v => v.Errors);

            foreach (var error in errors)
            {
                return Json(error.ErrorMessage);
            }

            return Json(true);
        }

        public async Task<IActionResult> ValidateEmailAsync(string email)
        {
            var validators = userManager.UserValidators;

            foreach (var validator in validators)
            {
                var user = new AppUser { Email = email };
                var result = await validator.ValidateAsync(userManager, user);

                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        if (error.Code.ToLower().Contains(nameof(email)))
                        {
                            ModelState.AddModelError(nameof(email), error.Description);
                        }
                    }
                }
            }

            var errors = ModelState.Values.SelectMany(v => v.Errors);

            foreach (var error in errors)
            {
                return Json(error.ErrorMessage);
            }

            return Json(true);
        }

        public async Task<IActionResult> ValidatePasswordAsync(string password)
        {
            var validators = userManager.PasswordValidators;

            foreach (var validator in validators)
            {
                var result = await validator.ValidateAsync(userManager, null, password);

                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(nameof(password), error.Description);
                    }
                }
            }

            var errors = ModelState.Values.SelectMany(v => v.Errors);

            foreach (var error in errors)
            {
                return Json(error.ErrorMessage);
            }

            return Json(true);
        }

        public async Task<IActionResult> ResendEmailConfirmationAsync()
        {
            var user = await userManager.GetUserAsync(User);

            if (user != null)
            {
                await SendEmailConfirmationAsync(user);
            }

            return RedirectToAction("Index", "Home");
        }

        public async Task SendEmailConfirmationAsync(AppUser user)
        {
            string token = await userManager.GenerateEmailConfirmationTokenAsync(user);
            string code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            string url = Url.Action(
                "ConfirmEmail",
                "Account",
                new { userId = user.Id, code },
                Request.Scheme);

            await emailService.SendAsync(
                user.Email,
                "Email verification",
                $"<a href=\"{url}\">Verify your email</a>",
                true);
        }

        public async Task<IActionResult> ConfirmEmailAsync(string userId, string code)
        {
            if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(code))
            {
                var user = await userManager.FindByIdAsync(userId);
                var token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));

                if (user != null)
                {
                    await userManager.ConfirmEmailAsync(user, token);
                }
            }

            return RedirectToAction("Index", "Home");
        }

        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPasswordAsync(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByNameAsync(model.UserName) ??
                       await userManager.FindByEmailAsync(model.UserName);

                if (user != null)
                {
                    string token = await userManager.GeneratePasswordResetTokenAsync(user);
                    string code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                    string url = Url.Action(
                        "ResetPassword",
                        "Account",
                        new { userId = user.Id, code },
                        Request.Scheme);

                    await emailService.SendAsync(
                        user.Email,
                        "Reset password",
                        $"<a href=\"{url}\">Reset your password</a>",
                        true);

                    return RedirectToAction("Login");
                }

                ModelState.AddModelError(nameof(model.UserName), appIdentityErrorDescriber.UserNotExists().Description);
            }

            return View(model);
        }

        public IActionResult ResetPassword(string userId, string code)
        {
            if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(code))
            {
                var token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
                var model = new ResetPasswordViewModel
                {
                    Id = userId,
                    Token = token
                };

                return View(model);
            }

            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPasswordAsync(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByIdAsync(model.Id);

                if (user != null)
                {
                    var result = await userManager.ResetPasswordAsync(
                        user,
                        model.Token,
                        model.Password);

                    if (result.Succeeded)
                    {
                        return RedirectToAction("Login");
                    }
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account");
            var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallbackAsync()
        {
            var info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("Register");
            }

            var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            if (result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }
            else if (result.IsLockedOut)
            {
                return RedirectToAction("ForgotPassword");
            }
            else
            {
                ViewBag.Provider = info.LoginProvider;

                string userName = info.Principal.FindFirstValue(ClaimTypes.Name),
                    email = info.Principal.FindFirstValue(ClaimTypes.Email);

                return View("ExternalLoginConfirmation", new ExternalLoginViewModel { Email = email });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmationAsync(ExternalLoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var info = await signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return RedirectToAction("Register");
                }

                IdentityResult result;
                var user = await userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    user = new AppUser
                    {
                        UserName = model.UserName,
                        Email = model.Email
                    };

                    result = await userManager.CreateAsync(user);
                    if (result.Succeeded)
                    {
                        result = await userManager.AddLoginAsync(user, info);
                        if (result.Succeeded)
                        {
                            await SendEmailConfirmationAsync(user);
                        }
                    }
                }

                await signInManager.SignInAsync(user, isPersistent: false);

                return RedirectToAction("Index", "Home");
            }

            return View(model);
        }

        public IActionResult ExternalLoginAccessDenied()
        {
            return View();
        }
    }
}
