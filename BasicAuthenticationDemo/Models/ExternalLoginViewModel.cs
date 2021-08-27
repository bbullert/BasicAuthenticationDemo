using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace BasicAuthenticationDemo.Models
{
    public class ExternalLoginViewModel
    {
        [Required(ErrorMessage = "Username is required")]
        [Remote("ValidateUserName", "Account")]
        [Display(Name = "Username")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [Remote("ValidateEmail", "Account")]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
}
