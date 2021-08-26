using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace DataAccess.Entities
{
    public class AppUser : IdentityUser
    {
        [Column(TypeName = "varchar(255)")]
        [MaxLength(255)]
        public override string PasswordHash { get; set; }

        [Column(TypeName = "varchar(255)")]
        [MaxLength(255)]
        public override string SecurityStamp { get; set; }

        [Column(TypeName = "varchar(255)")]
        [MaxLength(255)]
        public override string ConcurrencyStamp { get; set; }

        [Column(TypeName = "varchar(15)")]
        [MaxLength(15)]
        public override string PhoneNumber { get; set; }
    }
}
