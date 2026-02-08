using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApp_Core_Identity.Model;
using WebApp_Core_Identity.Services;

var builder = WebApplication.CreateBuilder(args);

// Register AuthDbContext with SQL Server
builder.Services.AddDbContext<AuthDbContext>(options =>
 options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString")));

// Register audit service
builder.Services.AddScoped<IAuditService, DbAuditService>();

// Register Recaptcha service
builder.Services.AddHttpClient();
builder.Services.AddSingleton<IRecaptchaService, GoogleRecaptchaService>();

// Configure Identity options (unique email, password policy, lockout)
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
 // User settings
 options.User.RequireUniqueEmail = true;

 // Password policy - min12 chars, upper, lower, digits, special
 options.Password.RequiredLength =12;
 options.Password.RequireUppercase = true;
 options.Password.RequireLowercase = true;
 options.Password.RequireDigit = true;
 options.Password.RequireNonAlphanumeric = true;

 // Lockout policy
 options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
 options.Lockout.MaxFailedAccessAttempts =3;
 options.Lockout.AllowedForNewUsers = true;

 // SignIn settings (adjust if you require confirmed email)
 options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();

var timeoutMinutes = builder.Configuration.GetValue<int>("Session:TimeoutMinutes",20);
var sessionTimeout = TimeSpan.FromMinutes(timeoutMinutes);

// Consolidated cookie configuration for Identity application cookie
builder.Services.ConfigureApplicationCookie(options =>
{
 options.Cookie.HttpOnly = true;
 options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
 options.ExpireTimeSpan = sessionTimeout; // session timeout
 options.SlidingExpiration = true;
 options.LoginPath = "/Login";
 options.AccessDeniedPath = "/Account/AccessDenied";

 // On signing in, ensure session is created in session tracker
 options.Events.OnSigningIn = async ctx =>
 {
 var sessionTracker = ctx.HttpContext.RequestServices.GetRequiredService<ISessionTracker>();
 var userManager = ctx.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
 var user = await userManager.GetUserAsync(ctx.Principal);
 if (user != null)
 {
 var sessionId = ctx.Principal.FindFirst("SessionId")?.Value ?? Guid.NewGuid().ToString();
 sessionTracker.CreateSession(user.Id, sessionId, ctx.Options.ExpireTimeSpan);
 }
 };

 options.Events.OnValidatePrincipal = async ctx =>
 {
 var sessionTracker = ctx.HttpContext.RequestServices.GetRequiredService<ISessionTracker>();
 var userManager = ctx.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
 var user = await userManager.GetUserAsync(ctx.Principal);
 if (user == null)
 {
 ctx.RejectPrincipal();
 return;
 }

 var sessionId = ctx.Principal.FindFirst("SessionId")?.Value ?? string.Empty;
 var result = sessionTracker.ValidateSession(user.Id, sessionId, out var remaining);
 if (result == SessionValidationResult.Expired)
 {
 // Log the session expiration event
 var audit = ctx.HttpContext.RequestServices.GetRequiredService<IAuditService>();
 await audit.LogEventAsync(user.Id, "SessionExpired", "User session expired", ctx.HttpContext);

 ctx.HttpContext.Response.Redirect("/Login?sessionExpired=1");
 ctx.RejectPrincipal();
 return;
 }
 else if (result == SessionValidationResult.Different)
 {
 // Multiple login detected: log and redirect to login with reason
 var audit = ctx.HttpContext.RequestServices.GetRequiredService<IAuditService>();
 await audit.LogEventAsync(user.Id, "SessionReplaced", "User session replaced by another login", ctx.HttpContext);

 ctx.HttpContext.Response.Redirect("/Login?otherLogin=1");
 ctx.RejectPrincipal();
 return;
 }
 // else valid - allow
 };

 // Customize redirect to login to mark sessionExpired when cookie existed
 options.Events.OnRedirectToLogin = ctx =>
 {
 if (ctx.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
 {
 ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
 return Task.CompletedTask;
 }

 var cookieName = ctx.Options.Cookie.Name ?? ".AspNetCore.Identity.Application";
 var hasAuthCookie = ctx.Request.Cookies.ContainsKey(cookieName);

 var redirectUri = ctx.RedirectUri;
 if (hasAuthCookie)
 {
 var separator = redirectUri.Contains('?') ? '&' : '?';
 redirectUri = redirectUri + separator + "sessionExpired=true";
 }

 ctx.Response.Redirect(redirectUri);
 return Task.CompletedTask;
 };
});

builder.Services.AddAuthorization(options =>
{
 options.AddPolicy("MustBelongToHRDepartment",
 policy => policy.RequireClaim("Department", "HR"));
});

builder.Services.AddDataProtection();

// Register credit card protector service
builder.Services.AddSingleton<ICreditCardProtector, CreditCardProtector>();

// Register session tracker (in-memory)
builder.Services.AddSingleton<ISessionTracker, InMemorySessionTracker>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
 app.UseExceptionHandler("/Error");
 app.UseHsts();
}

app.UseAuthentication();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();

app.Run();
