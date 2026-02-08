using System;

namespace WebApp_Core_Identity.Services
{
 public enum SessionValidationResult
 {
 Valid,
 Expired,
 Different
 }

 public interface ISessionTracker
 {
 void CreateSession(string userId, string sessionId, TimeSpan timeout);
 SessionValidationResult ValidateSession(string userId, string sessionId, out TimeSpan? remaining);
 void RemoveSession(string userId);
 }
}