using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BasicAuthenticationDemo.Services.Validation
{
    public class AppPasswordValidator<TUser> : IPasswordValidator<TUser> where TUser : IdentityUser
    {
        private readonly AppIdentityErrorDescriber appIdentityErrorDescriber;

        public AppPasswordValidator(AppIdentityErrorDescriber appIdentityErrorDescriber)
        {
            this.appIdentityErrorDescriber = appIdentityErrorDescriber;

            RequiredLength = 5;
            MaximumLength = 20;
            AllowedCharacters = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./\\:;<=>?@[]^_`{|}~";
        }

        public int RequiredLength { get; set; }

        public int MaximumLength { get; set; }

        public string AllowedCharacters { get; set; }

        public Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            var errors = new List<IdentityError>();

            if (string.IsNullOrWhiteSpace(password))
            {
                errors.Add(appIdentityErrorDescriber.InvalidPassword());
            }
            if (password.Length > MaximumLength)
            {
                errors.Add(appIdentityErrorDescriber.PasswordTooLong(MaximumLength));
            }
            if (password.Except(AllowedCharacters).Any())
            {
                errors.Add(appIdentityErrorDescriber.InvalidPassword());
            }

            var result = errors.Count > 0 ? IdentityResult.Failed(errors.ToArray()) : IdentityResult.Success;

            return Task.FromResult(result);
        }
    }
}
