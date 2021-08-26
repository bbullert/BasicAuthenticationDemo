using BasicAuthenticationDemo.Models;
using BasicAuthenticationDemo.Services.Validation;
using DataAccess.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BasicAuthenticationDemo.Controllers
{
    public class AccountController : Controller
    {
        private readonly ILogger<AccountController> logger;
        private readonly UserManager<AppUser> userManager;
        private readonly SignInManager<AppUser> signInManager;
        private readonly AppIdentityErrorDescriber appIdentityErrorDescriber;

        public AccountController(
            ILogger<AccountController> logger,
            UserManager<AppUser> userManager,
            SignInManager<AppUser> signInManager,
            AppIdentityErrorDescriber appIdentityErrorDescriber)
        {
            this.logger = logger;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.appIdentityErrorDescriber = appIdentityErrorDescriber;
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
                    // todo: send email confirmation

                    return RedirectToAction("Login");
                }
            }

            return View(model);
        }
    }
}
