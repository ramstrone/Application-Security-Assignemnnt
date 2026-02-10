using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace WebApp_Core_Identity.ViewModels
{
    public class Register
    {
        [Required]
        [EmailAddress]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [MinLength(12, ErrorMessage = "Password must be at least12 characters long")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match")]
        public string ConfirmPassword { get; set; }

        [Required]
        [MaxLength(100)]
        public string FirstName { get; set; }

        [Required]
        [MaxLength(100)]
        public string LastName { get; set; }

        [Required]
        [Phone]
        [RegularExpression(@"^\+?[0-9 \-\(\)]{7,20}$", ErrorMessage = "Invalid phone number")]
        [MaxLength(20)]
        public string MobileNumber { get; set; }

        [Required]
        [MaxLength(500)]
        [DataType(DataType.MultilineText)]
        public string BillingAddress { get; set; }

        [Required]
        [MaxLength(500)]
        [DataType(DataType.MultilineText)]
        public string ShippingAddress { get; set; }

        // Sensitive: store encrypted value in DB. Keep as string here and encrypt server-side before saving.
        [Required]
        [DataType(DataType.CreditCard)]
        [StringLength(25, MinimumLength =12, ErrorMessage = "Credit card length invalid")]
        public string CreditCard { get; set; }

        // Photo upload (.jpg only) - will be handled in the page handler. Optional now.
        public IFormFile Photo { get; set; }
    }
}
