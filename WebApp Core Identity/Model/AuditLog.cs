using System;
using System.ComponentModel.DataAnnotations;

namespace WebApp_Core_Identity.Model
{
 public class AuditLog
 {
     [Key]
     public int Id { get; set; }

     [MaxLength(450)]
     public string UserId { get; set; } = string.Empty;

     [MaxLength(100)]
     public string EventType { get; set; } = string.Empty;

     [MaxLength(2000)]
     public string Description { get; set; } = string.Empty;

     [MaxLength(200)]
     public string IpAddress { get; set; } = string.Empty;

    [MaxLength(1000)]
     public string UserAgent { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
 }
}
