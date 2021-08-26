using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace BasicAuthenticationDemo.Services.Validation
{
    public class AppUserValidator<TUser> : IUserValidator<TUser> where TUser : IdentityUser
    {
        private readonly AppIdentityErrorDescriber appIdentityErrorDescriber;

        public AppUserValidator(AppIdentityErrorDescriber appIdentityErrorDescriber)
        {
            this.appIdentityErrorDescriber = appIdentityErrorDescriber;

            UserNameRequiredLength = 4;
            UserNameMaximumLength = 20;
            EmailMaximumLength = 50;
        }

        public int UserNameRequiredLength { get; set; }

        public int UserNameMaximumLength { get; set; }

        public int EmailMaximumLength { get; set; }

        public virtual async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user)
        {
            var errors = new List<IdentityError>();

            await ValidateUserName(manager, user, errors);

            if (manager.Options.User.RequireUniqueEmail)
            {
                await ValidateEmail(manager, user, errors);
            }

            return errors.Count > 0 ? IdentityResult.Failed(errors.ToArray()) : IdentityResult.Success;
        }

        private async Task ValidateUserName(UserManager<TUser> manager, TUser user, ICollection<IdentityError> errors)
        {
            var userName = await manager.GetUserNameAsync(user);

            if (string.IsNullOrWhiteSpace(userName))
            {
                errors.Add(appIdentityErrorDescriber.InvalidUserName(userName));
            }
            else if (userName.Length < UserNameRequiredLength)
            {
                errors.Add(appIdentityErrorDescriber.UserNameTooShort(UserNameRequiredLength));
            }
            else if (userName.Length > UserNameMaximumLength)
            {
                errors.Add(appIdentityErrorDescriber.UserNameTooLong(UserNameMaximumLength));
            }
            else if (!string.IsNullOrEmpty(manager.Options.User.AllowedUserNameCharacters) &&
                userName.Except(manager.Options.User.AllowedUserNameCharacters).Any())
            {
                errors.Add(appIdentityErrorDescriber.InvalidUserName(userName));
            }
            else
            {
                var owner = await manager.FindByNameAsync(userName);
                if (owner != null &&
                    !string.Equals(await manager.GetUserIdAsync(owner), await manager.GetUserIdAsync(user)))
                {
                    errors.Add(appIdentityErrorDescriber.DuplicateUserName(userName));
                }
            }
        }

        private async Task ValidateEmail(UserManager<TUser> manager, TUser user, List<IdentityError> errors)
        {
            var email = await manager.GetEmailAsync(user);

            if (string.IsNullOrWhiteSpace(email))
            {
                errors.Add(appIdentityErrorDescriber.InvalidEmail(email));
            }
            else if (email.Length > EmailMaximumLength)
            {
                errors.Add(appIdentityErrorDescriber.EmailTooLong(EmailMaximumLength));
            }
            else if (!new EmailAddressAttribute().IsValid(email))
            {
                errors.Add(appIdentityErrorDescriber.InvalidEmail(email));
            }
            else
            {
                var owner = await manager.FindByEmailAsync(email);
                if (owner != null &&
                    !string.Equals(await manager.GetUserIdAsync(owner), await manager.GetUserIdAsync(user)))
                {
                    errors.Add(appIdentityErrorDescriber.DuplicateEmail(email));
                }
            }
        }
    }
}
