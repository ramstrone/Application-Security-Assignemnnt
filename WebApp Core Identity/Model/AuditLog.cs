using System;
using System.ComponentModel.DataAnnotations;

namespace WebApp_Core_Identity.Model
{
 public class AuditLog
 {
 [Key]
 public int Id { get; set; }

 [MaxLength(450)]
 public string UserId { get; set; }

 [MaxLength(100)]
 public string EventType { get; set; }

 [MaxLength(2000)]
 public string Description { get; set; }

 [MaxLength(200)]
 public string IpAddress { get; set; }

 [MaxLength(1000)]
 public string UserAgent { get; set; }

 public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
 }
}
