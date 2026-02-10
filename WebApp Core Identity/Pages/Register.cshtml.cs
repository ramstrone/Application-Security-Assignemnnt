using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApp_Core_Identity.ViewModels;
using WebApp_Core_Identity.Model;
using Microsoft.AspNetCore.Hosting;
using System.IO;
using Microsoft.Extensions.Logging;
using System.Linq;
using WebApp_Core_Identity.Services;
using System;
using System.Threading.Tasks;

namespace WebApp_Core_Identity.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IWebHostEnvironment env;
        private readonly ILogger<RegisterModel> logger;
        private readonly ICreditCardProtector creditCardProtector;

        [BindProperty]
        public Register RModel { get; set; } = new Register();

        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, IWebHostEnvironment env, ILogger<RegisterModel> logger, ICreditCardProtector creditCardProtector)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this.env = env;
            this.logger = logger;
            this.creditCardProtector = creditCardProtector;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Validate photo metadata only when provided
            if (RModel.Photo != null && RModel.Photo.Length >0)
            {
                var ext = Path.GetExtension(RModel.Photo.FileName).ToLowerInvariant();
                if (ext != ".jpg")
                {
                    ModelState.AddModelError("RModel.Photo", "Only .jpg images are allowed");
                }
                else if (RModel.Photo.Length >2 *1024 *1024) //2MB limit
                {
                    ModelState.AddModelError("RModel.Photo", "Image size must be 2MB or less");
                }
                else if (RModel.Photo.ContentType != "image/jpeg")
                {
                    ModelState.AddModelError("RModel.Photo", "Only JPEG content type is allowed");
                }
                else
                {
                    // Verify JPEG magic bytes
                    using (var ms = new MemoryStream())
                    {
                        await RModel.Photo.CopyToAsync(ms);
                        var bytes = ms.ToArray();
                        if (bytes.Length <3 || bytes[0] !=0xFF || bytes[1] !=0xD8 || bytes[2] !=0xFF)
                        {
                            ModelState.AddModelError("RModel.Photo", "File is not a valid JPEG image");
                        }
                        // Reset stream position so later saving can read it again
                        ms.Position =0;
                        // Replace RModel.Photo with a new stream-backed IFormFile instance if needed
                        // But for simplicity we'll write from the original stream later when saving
                    }
                }
            }

            // If model is invalid, return the page so validation messages show
            if (!ModelState.IsValid)
            {
                var entries = ModelState.Where(kvp => kvp.Value.Errors.Count >0)
                .Select(kvp => $"{kvp.Key}: {string.Join(", ", kvp.Value.Errors.Select(e => e.ErrorMessage))}");
                var debug = string.Join(" | ", entries);
                logger.LogInformation("ModelState invalid during registration: {Debug}", debug);
                return Page();
            }

            // Sanitize free-text inputs (addresses) before saving
            RModel.BillingAddress = InputSanitizer.Sanitize(RModel.BillingAddress);
            RModel.ShippingAddress = InputSanitizer.Sanitize(RModel.ShippingAddress);

            var email = (RModel.Email ?? string.Empty).Trim();

            // Check for duplicate email before attempting to create user
            var existingByEmail = await userManager.FindByEmailAsync(email);
            if (existingByEmail != null)
            {
                ModelState.AddModelError(string.Empty, "Email is already registered. If you forgot your password use the password reset flow.");
                return Page();
            }

            string savedFileName = null;

            // If we reach here, all server-side validation passed. Save photo (if present) and then create user.
            if (RModel.Photo != null && RModel.Photo.Length >0)
            {
                var ext = Path.GetExtension(RModel.Photo.FileName).ToLowerInvariant();
                var uploads = Path.Combine(env.WebRootPath ?? "wwwroot", "uploads");
                if (!Directory.Exists(uploads)) Directory.CreateDirectory(uploads);

                var fileName = Guid.NewGuid().ToString() + ext;
                var filePath = Path.Combine(uploads, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await RModel.Photo.CopyToAsync(stream);
                }

                savedFileName = fileName;
            }

            // Protect (encrypt) credit card before saving
            string protectedCard = null;
            if (!string.IsNullOrEmpty(RModel.CreditCard))
            {
                try
                {
                    protectedCard = creditCardProtector.Protect(RModel.CreditCard);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to protect credit card");
                    ModelState.AddModelError("", "An error occurred processing the credit card.");
                    return Page();
                }
            }

            var user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                FirstName = RModel.FirstName,
                LastName = RModel.LastName,
                MobileNumber = RModel.MobileNumber,
                BillingAddress = RModel.BillingAddress,
                ShippingAddress = RModel.ShippingAddress,
                PhotoPath = savedFileName ?? string.Empty,
                CreditCardNo = protectedCard // store encrypted value
            };

            // Ensure Admin role exists (use RoleExistsAsync or FindByNameAsync)
            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                var roleResult = await roleManager.CreateAsync(new IdentityRole("Admin"));
                if (!roleResult.Succeeded)
                {
                    ModelState.AddModelError("", "Create role admin failed");
                    return Page();
                }
            }

            var result = await userManager.CreateAsync(user, RModel.Password);
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(user, "Admin");
                await signInManager.SignInAsync(user, isPersistent: false);

                // Re-fetch the user to ensure PasswordHash is populated from store
                var createdUser = await userManager.FindByEmailAsync(email);
                var hash = createdUser?.PasswordHash;
                if (!string.IsNullOrEmpty(hash))
                {
                    var ph = HttpContext.RequestServices.GetRequiredService<IPasswordHistoryService>();
                    await ph.AddAsync(createdUser.Id, hash);
                    await ph.TrimAsync(createdUser.Id,2); // keep last2
                }

                if (createdUser != null)
                {
                    createdUser.PasswordChangedUtc = DateTime.UtcNow;
                    await userManager.UpdateAsync(createdUser);
                }

                return RedirectToPage("Index");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return Page();
        }
    }
}
