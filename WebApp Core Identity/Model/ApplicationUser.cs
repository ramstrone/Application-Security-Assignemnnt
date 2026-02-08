using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WebApp_Core_Identity.Model
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(100)]
        public string FirstName { get; set; }

        [MaxLength(100)]
        public string LastName { get; set; }

        [Phone]
        [MaxLength(20)]
        public string MobileNumber { get; set; }

        [MaxLength(500)]
        public string BillingAddress { get; set; }

        [MaxLength(500)]
        public string ShippingAddress { get; set; }

        [MaxLength(260)]
        public string PhotoPath { get; set; }

        // Sensitive: store encrypted value (encrypt before saving)
        [MaxLength(1000)]
        public string CreditCardNo { get; set; }
    }
}
