using Microsoft.AspNetCore.Authentication;
using System.ComponentModel.DataAnnotations;

namespace Identity.Models
{
    public class ViewModels
    {
    }

    public class RegisterViewModel
    {
        [Required(ErrorMessage = "First Name is Required")]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }
        [Display(Name = "Last Name")]
        public string? LastName { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "Password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }

    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }
        public string? ReturnUrl { get; set; }
        // AuthenticationScheme is in Microsoft.AspNetCore.Authentication namespace
        public IList<AuthenticationScheme>? ExternalLogins { get; set; }
    }

    public class CreateRoleViewModel
    {
        [Required]
        [Display(Name = "Role")]
        public string RoleName { get; set; }
        public string? Description { get; set; }
    }

    public class EditRoleViewModel
    {
        [Required]
        public string Id { get; set; }
        [Required(ErrorMessage = "Role Name is Required")]
        public string RoleName { get; set; }
        public string? Description { get; set; }
        public List<string>? Users { get; set; }
        public List<string>? Claims { get; set; }

    }

    public class UserRoleViewModel
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public bool IsSelected { get; set; }
    }
    public class EditUserViewModel
    {
        //To avoid NullReferenceExceptions at runtime,
        //initialise Claims and Roles with a new list in the constructor.
        public EditUserViewModel()
        {
            Claims = new List<string>();
            Roles = new List<string>();
        }
        [Required]
        public string Id { get; set; }
        [Required]
        [Display(Name = "User Name")]
        public string UserName { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Display(Name = "First Name")]
        public string? FirstName { get; set; }
        [Display(Name = "Last Name")]
        public string? LastName { get; set; }
        public List<string> Claims { get; set; }
        public IList<string> Roles { get; set; }
    }
    public class UserRolesViewModel
    {
        public string RoleId { get; set; }
        public string RoleName { get; set; }
        public string? Description { get; set; }
        public bool IsSelected { get; set; }
    }

    public class UserClaim
    {
        public string ClaimType { get; set; }
        public bool IsSelected { get; set; }
    }

    public class UserClaimsViewModel
    {
        public UserClaimsViewModel()
        {
            //To Avoid runtime exception, we are initializing the Cliams property
            Claims = new List<UserClaim>();
        }

        public string UserId { get; set; }
        public List<UserClaim> Claims { get; set; }
    }

    public class RoleClaim
    {
        public string ClaimType { get; set; }
        public bool IsSelected { get; set; }
    }

    public class RoleClaimsViewModel
    {
        public RoleClaimsViewModel()
        {
            //To Avoid runtime exception, we are initializing the Cliams property
            Claims = new List<RoleClaim>();
        }
        public string RoleId { get; set; }
        public List<RoleClaim> Claims { get; set; }
    }


}
