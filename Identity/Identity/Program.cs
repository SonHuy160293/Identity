using Identity.Interfaces;
using Identity.Models;
using Identity.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

//Configure Entity Framework Core
var connectionString = builder.Configuration.GetConnectionString("SQLServerIdentityConnection") ?? throw new InvalidOperationException("Connection string 'SQLServerIdentityConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));


//register identity service
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
                options.Password.RequiredUniqueChars = 4;
                // Other settings can be configured here

                options.SignIn.RequireConfirmedEmail = true;
            })
                    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

// Configure the Application Cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    // If the LoginPath isn't set, ASP.NET Core defaults the path to /Account/Login.
    options.LoginPath = "/Account/Login"; // Set your login path here
    options.AccessDeniedPath = "/Account/AccessDenied";
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("EditRolePolicy", policy => policy.RequireClaim("Edit Role"));
    options.AddPolicy("DeleteRolePolicy", policy => policy.RequireClaim("Delete Role"));
});


var GoogleClientId = builder.Configuration["Google:AppId"];
var GoogleClientSecret = builder.Configuration["Google:AppSecret"];
builder.Services.AddAuthentication()
.AddGoogle(options =>
{
    options.ClientId = GoogleClientId;
    options.ClientSecret = GoogleClientSecret;
    // Ensure this matches the Google Cloud Console
    // You can set other options as needed.
});

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.Lax; // Ensure cookies are sent properly
});

builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.AddControllersWithViews();


var app = builder.Build();

// Configure the HTTP request pipeline.
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
}
app.UseStaticFiles();

app.UseRouting();

//Configuring Authentication Middleware to the Request Pipeline
app.UseAuthentication();
app.UseAuthorization();

app.UseCookiePolicy();


app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
