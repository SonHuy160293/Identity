using Identity.Interfaces;
using Identity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Identity.Controllers
{
    public class AccountController : Controller
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }


        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = registerViewModel.Email,
                    Email = registerViewModel.Email,
                    FirstName = registerViewModel.FirstName,
                    LastName = registerViewModel.LastName
                };

                //save user to db
                var result = await _userManager.CreateAsync(user, registerViewModel.Password);


                // If user is successfully created, sign-in the user using
                // SignInManager and redirect to index action of HomeController
                if (result.Succeeded)
                {


                    //Then send the Confirmation Email to the User
                    await SendConfirmationEmail(registerViewModel.Email, user);

                    // If the user is signed in and in the Admin role, then it is
                    // the Admin user that is creating a new user. 
                    // So redirect the Admin user to ListUsers action of Administration Controller
                    if (_signInManager.IsSignedIn(User) && User.IsInRole("Admin"))
                    {
                        return RedirectToAction("ListUsers", "Administration");
                    }

                    //If it is not Admin user, then redirect the user to RegistrationSuccessful View
                    return View("RegistrationSuccessful");
                }

                // If there are any errors, add them to the ModelState object
                // which will be displayed by the validation summary tag helper
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }


            }



            return View(registerViewModel);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string? ReturnUrl = null)
        {


            var externalLogins = await _signInManager.GetExternalAuthenticationSchemesAsync();

            LoginViewModel model = new LoginViewModel
            {
                ReturnUrl = ReturnUrl,
                ExternalLogins = externalLogins.ToList()
            };

            return View(model);
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            //This call will generate a URL that directs to the ExternalLoginCallback action method in the Account controller
            //with a route parameter of ReturnUrl set to the value of returnUrl.
            var redirectUrl = Url.Action(action: "ExternalLoginCallback", controller: "Account", values: new { ReturnUrl = returnUrl });

            // Configure the redirect URL, provider and other properties
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            //This will redirect the user to the external provider's login page
            return new ChallengeResult(provider, properties);
        }

        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string? returnUrl, string? remoteError)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            LoginViewModel loginViewModel = new LoginViewModel
            {
                ReturnUrl = returnUrl,
                ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
            };

            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");

                return View("Login", loginViewModel);
            }

            // Get the login information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                ModelState.AddModelError(string.Empty, "Error loading external login information.");

                return View("Login", loginViewModel);
            }

            // Email Confirmation Section
            // Get the email claim from external login provider (Google, Facebook etc)
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            ApplicationUser? user;
            if (email != null)
            {
                // Find the user
                user = await _userManager.FindByEmailAsync(email);
                // If the user exists in our database and email is not confirmed,
                // display login view with validation error
                if (user != null && !user.EmailConfirmed)
                {
                    ModelState.AddModelError(string.Empty, "Email not confirmed yet");
                    return View("Login", loginViewModel);
                }
            }

            // If the user already has a login (i.e., if there is a record in AspNetUserLogins table)
            // then sign-in the user with this external login provider
            var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider,
                info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            if (signInResult.Succeeded)
            {
                return LocalRedirect(returnUrl);
            }

            // If there is no record in AspNetUserLogins table, the user may not have a local account
            else
            {

                if (email != null)
                {
                    // Create a new user without password if we do not have a user already
                    user = await _userManager.FindByEmailAsync(email);

                    if (user == null)
                    {
                        user = new ApplicationUser
                        {
                            UserName = info.Principal.FindFirstValue(ClaimTypes.Email),
                            Email = info.Principal.FindFirstValue(ClaimTypes.Email),
                            FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName),
                            LastName = info.Principal.FindFirstValue(ClaimTypes.Surname),
                        };

                        //This will create a new user into the AspNetUsers table without password
                        await _userManager.CreateAsync(user);
                    }

                    // Add a login (i.e., insert a row for the user in AspNetUserLogins table)
                    await _userManager.AddLoginAsync(user, info);


                    //Then send the Confirmation Email to the User
                    await SendConfirmationEmail(email, user);


                    //Then Signin the User
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return LocalRedirect(returnUrl);
                }

                // If we cannot find the user email we cannot continue
                ViewBag.ErrorTitle = $"Email claim not received from: {info.LoginProvider}";
                ViewBag.ErrorMessage = "Please contact support on info@dotnettutorials.net";

                return View("Error");
            }
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel, string? ReturnUrl)
        {
            if (ModelState.IsValid)
            {

                //First Fetch the User Details by Email Id
                var user = await _userManager.FindByEmailAsync(loginViewModel.Email);
                //Then Check if User Exists, EmailConfirmed and Password Is Valid
                //CheckPasswordAsync: Returns a flag indicating whether the given password is valid for the specified user.
                if (user != null && !user.EmailConfirmed &&
                            (await _userManager.CheckPasswordAsync(user, loginViewModel.Password)))
                {
                    ModelState.AddModelError(string.Empty, "Email not confirmed yet");
                    return View(loginViewModel);
                }

                var result = await _signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Password, loginViewModel.RememberMe, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    // Handle successful login
                    // Check if the ReturnUrl is not null and is a local URL
                    if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
                    {
                        return Redirect(ReturnUrl);
                    }
                    else
                    {
                        // Redirect to default page
                        return RedirectToAction("Index", "Home");
                    }
                }

                if (result.RequiresTwoFactor)
                {
                    // Handle two-factor authentication case
                }
                if (result.IsLockedOut)
                {
                    // Handle lockout scenario
                }
                else
                {
                    // Handle failure
                    ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
                    return View(loginViewModel);
                }
            }

            return View(loginViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }

        private async Task SendConfirmationEmail(string? email, ApplicationUser? user)
        {
            //generate token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            //build email confirmation link which include call back url
            var confirmationLink = Url.Action("ConfirmEmail", "Account", new
            {
                UserId = user.Id,
                Token = token
            }, protocol: HttpContext.Request.Scheme);

            //Send the Confirmation Email to the User Email Id
            await _emailSender.SendEmailAsync(email,
                "Confirm Your Email",
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(confirmationLink)}'>clicking here</a>.",
                true);

        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (userId is null || token is null)
            {
                ViewBag.Message = "The link is invalid or expired";
            }

            //find user by id
            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                ViewBag.ErrorMessage = $"The User ID {userId} is Invalid";
                return View("NotFound");
            }

            //call the confirmation method to mark the email as confirmed
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                ViewBag.Message = "Thank you for confirming your email";
                return View();
            }

            ViewBag.Message = "Email cannot be confirmed";
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResendConfirmationEmail(bool isResend = true)
        {
            if (isResend)
            {
                ViewBag.Message = "Resend Confirmation Email";
            }
            else
            {
                ViewBag.Message = "Send Confirmation Email";
            }
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResendConfirmationEmail(string Email)
        {
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null || await _userManager.IsEmailConfirmedAsync(user))
            {
                // Handle the situation when the user does not exist or Email already confirmed.
                // For security, don't reveal that the user does not exist or Email is already confirmed
                return View("ConfirmationEmailSent");
            }

            //Then send the Confirmation Email to the User
            await SendConfirmationEmail(Email, user);

            return View("ConfirmationEmailSent");
        }
    }
}
