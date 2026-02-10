using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WebApp_Core_Identity.Model
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [MaxLength(100)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [MaxLength(100)]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [Phone]
        [MaxLength(8)]
        public string MobileNumber { get; set; } = string.Empty;

        [Required]
        [MaxLength(500)]
        public string BillingAddress { get; set; } = string.Empty;

        [Required]
        [MaxLength(500)]
        public string ShippingAddress { get; set; } = string.Empty;

        [Required]
        [MaxLength(260)]
        public string PhotoPath { get; set; } = string.Empty;

        // Sensitive: store encrypted value (encrypt before saving)
        [Required]
        [MaxLength(1000)]
        public string CreditCardNo { get; set; } = string.Empty;

        public DateTime? PasswordChangedUtc { get; set; }
    }
}
