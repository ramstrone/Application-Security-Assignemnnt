using Microsoft.AspNetCore.Authentication;
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
 var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
 var user = await userManager.GetUserAsync(ctx.Principal);
 logger.LogInformation("OnSigningIn for user principal: {name}", ctx.Principal?.Identity?.Name);
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
 var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
 var user = await userManager.GetUserAsync(ctx.Principal);
 logger.LogInformation("OnValidatePrincipal invoked. RequestPath={path}, UserIdentity={name}", ctx.HttpContext.Request.Path, ctx.Principal?.Identity?.Name);
 if (user == null)
 {
 logger.LogInformation("User not found during validation, rejecting principal.");
 ctx.RejectPrincipal();
 return;
 }

 // Enforce maximum password age: require change if expired
 var config = ctx.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
 var maxAgeMinutes = config.GetValue<int>("PasswordPolicy:MaxAgeMinutes",300);
 if (!string.IsNullOrEmpty(user.Id))
 {
 if (!user.PasswordChangedUtc.HasValue || DateTime.UtcNow - user.PasswordChangedUtc.Value > TimeSpan.FromMinutes(maxAgeMinutes))
 {
 // Force password change: sign out and redirect to login so user can re-authenticate and then change password
 await ctx.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
 logger.LogInformation("Password expired for user {userId}; signing out and redirecting to Login (mustChangePassword flag).", user.Id);

 if (!ctx.HttpContext.Request.Path.StartsWithSegments("/Account/ChangePassword", StringComparison.OrdinalIgnoreCase))
 {
 ctx.HttpContext.Response.Redirect("/Login?mustChangePassword=1");
 }

 ctx.RejectPrincipal();
 return;
 }
 }

 var sessionId = ctx.Principal.FindFirst("SessionId")?.Value ?? string.Empty;
 var result = sessionTracker.ValidateSession(user.Id, sessionId, out var remaining);
 if (result == SessionValidationResult.Expired)
 {
 // Log the session expiration event
 var audit = ctx.HttpContext.RequestServices.GetRequiredService<IAuditService>();
 await audit.LogEventAsync(user.Id, "SessionExpired", "User session expired", ctx.HttpContext);

 // Sign out the application cookie to clear it and avoid redirect loops
 await ctx.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
 logger.LogInformation("Session expired for user {userId}; signing out and redirecting to Login.", user.Id);

 // Only redirect if we're not already on the login page
 if (!ctx.HttpContext.Request.Path.Equals("/Login", StringComparison.OrdinalIgnoreCase))
 {
 ctx.HttpContext.Response.Redirect("/Login?sessionExpired=1");
 }
 ctx.RejectPrincipal();
 return;
 }
 else if (result == SessionValidationResult.Different)
 {
 // Multiple login detected: log and redirect to login with reason
 var audit = ctx.HttpContext.RequestServices.GetRequiredService<IAuditService>();
 await audit.LogEventAsync(user.Id, "SessionReplaced", "User session replaced by another login", ctx.HttpContext);

 // Sign out to clear cookie and avoid loops
 await ctx.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
 logger.LogInformation("Session replaced for user {userId}; signing out and redirecting to Login.", user.Id);

 if (!ctx.HttpContext.Request.Path.Equals("/Login", StringComparison.OrdinalIgnoreCase))
 {
 ctx.HttpContext.Response.Redirect("/Login?otherLogin=1");
 }
 ctx.RejectPrincipal();
 return;
 }
 // else valid - allow
 };

 // Customize redirect to login to mark sessionExpired when cookie existed
 options.Events.OnRedirectToLogin = ctx =>
 {
 var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
 logger.LogInformation("OnRedirectToLogin invoked. RequestPath={path}", ctx.Request.Path);

 // If the request is for the login page already, do not redirect again
 if (ctx.Request.Path.Equals("/Login", StringComparison.OrdinalIgnoreCase))
 {
 logger.LogInformation("Already on /Login, skipping redirect.");
 return Task.CompletedTask;
 }

 if (ctx.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
 {
 ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
 return Task.CompletedTask;
 }

 var cookieName = ctx.Options.Cookie.Name ?? ".AspNetCore.Identity.Application";
 var hasAuthCookie = ctx.Request.Cookies.ContainsKey(cookieName);

 var redirectUri = ctx.RedirectUri;
 // avoid appending the same flag multiple times
 if (hasAuthCookie && !redirectUri.Contains("sessionExpired=true") && !redirectUri.Contains("otherLogin=1"))
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

// Add this line:
builder.Services.AddRazorPages();
builder.Services.AddScoped<IPasswordHistoryService, PasswordHistoryService>();
builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection("Smtp"));
builder.Services.AddTransient<IEmailSender, SmtpEmailSender>();

var app = builder.Build();

// Diagnostic middleware to log each request and response to help find redirect loops
app.Use(async (ctx, next) =>
{
 var logger = ctx.RequestServices.GetRequiredService<ILogger<Program>>();
 var hasCookie = ctx.Request.Cookies.ContainsKey(".AspNetCore.Identity.Application");
 logger.LogInformation("Incoming request {method} {path} Authenticated={auth} HasCookie={hasCookie}", ctx.Request.Method, ctx.Request.Path, ctx.User?.Identity?.IsAuthenticated, hasCookie);

 await next();

 var location = ctx.Response.Headers.ContainsKey("Location") ? ctx.Response.Headers["Location"].ToString() : string.Empty;
 logger.LogInformation("Outgoing response {status} Location={location}", ctx.Response.StatusCode, location);
});

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
 app.UseExceptionHandler("/Error");
 app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Add status code pages to re-execute to our error handler for404/403/etc
app.UseStatusCodePagesWithReExecute("/Error/{0}");

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
