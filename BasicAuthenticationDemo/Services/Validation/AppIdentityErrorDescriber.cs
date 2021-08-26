using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BasicAuthenticationDemo.Services.Validation
{
    public class AppIdentityErrorDescriber : IdentityErrorDescriber
    {
        public virtual IdentityError InvalidUserName()
        {
            return new IdentityError
            {
                Code = nameof(InvalidUserName),
                Description = "Password must consist only of alphanumeric and _ character"
            };
        }

        public override IdentityError DuplicateUserName(string email)
        {
            return new IdentityError
            {
                Code = nameof(DuplicateUserName),
                Description = "Username is already in use"
            };
        }

        public virtual IdentityError UserNameTooShort(int value)
        {
            return new IdentityError
            {
                Code = nameof(UserNameTooShort),
                Description = $"Username must be at least {value} characters long"
            };
        }

        public virtual IdentityError UserNameTooLong(int value)
        {
            return new IdentityError
            {
                Code = nameof(UserNameTooLong),
                Description = $"Username must be at most {value} characters long"
            };
        }

        public virtual IdentityError InvalidUserNameOrPassword()
        {
            return new IdentityError
            {
                Code = nameof(InvalidUserNameOrPassword),
                Description = "Invalid username or password"
            };
        }

        public override IdentityError InvalidEmail(string email)
        {
            return new IdentityError
            {
                Code = nameof(InvalidEmail),
                Description = "Invalid email address"
            };
        }

        public override IdentityError DuplicateEmail(string email)
        {
            return new IdentityError
            {
                Code = nameof(DuplicateEmail),
                Description = "Email address is already in use"
            };
        }

        public virtual IdentityError EmailTooLong(int value)
        {
            return new IdentityError
            {
                Code = nameof(EmailTooLong),
                Description = $"Email must be at most {value} characters long"
            };
        }

        public virtual IdentityError InvalidPassword()
        {
            return new IdentityError
            {
                Code = nameof(InvalidPassword),
                Description = "Password must consist only of alphanumeric, special characters and spaces"
            };
        }

        public override IdentityError PasswordTooShort(int value)
        {
            return new IdentityError
            {
                Code = nameof(PasswordTooShort),
                Description = $"Password must be at least {value} characters long"
            };
        }

        public virtual IdentityError PasswordTooLong(int value)
        {
            return new IdentityError
            {
                Code = nameof(PasswordTooLong),
                Description = $"Password must be at most {value} characters long"
            };
        }

        public override IdentityError PasswordRequiresLower()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresLower),
                Description = "Password must have at least one lowercase"
            };
        }

        public override IdentityError PasswordRequiresUpper()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresUpper),
                Description = "Password must have at least one uppercase"
            };
        }

        public override IdentityError PasswordRequiresDigit()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresDigit),
                Description = "Password must have at least one digit"
            };
        }

        public override IdentityError PasswordRequiresNonAlphanumeric()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresNonAlphanumeric),
                Description = "Password must have at least one non alphanumeric character"
            };
        }

        public virtual IdentityError UserNotExists()
        {
            return new IdentityError
            {
                Code = nameof(UserNotExists),
                Description = "User doesn't exists"
            };
        }
    }
}
