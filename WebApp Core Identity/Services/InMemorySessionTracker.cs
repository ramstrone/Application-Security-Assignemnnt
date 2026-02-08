using System;
using System.Collections.Concurrent;
using System.Threading;

namespace WebApp_Core_Identity.Services
{
 // Simple in-memory session tracker. Not suitable for multi-server deployments.
 public class InMemorySessionTracker : ISessionTracker
 {
 private record SessionInfo(string SessionId, DateTime Expires);
 private readonly ConcurrentDictionary<string, SessionInfo> sessions = new();

 public void CreateSession(string userId, string sessionId, TimeSpan timeout)
 {
 var info = new SessionInfo(sessionId, DateTime.UtcNow.Add(timeout));
 sessions.AddOrUpdate(userId, info, (k, v) => info);
 }

 public SessionValidationResult ValidateSession(string userId, string sessionId, out TimeSpan? remaining)
 {
 remaining = null;
 if (!sessions.TryGetValue(userId, out var info))
 return SessionValidationResult.Expired;

 if (info.SessionId != sessionId)
 return SessionValidationResult.Different;

 var now = DateTime.UtcNow;
 if (info.Expires < now)
 {
 sessions.TryRemove(userId, out _);
 return SessionValidationResult.Expired;
 }
 remaining = info.Expires - now;
 return SessionValidationResult.Valid;
 }

 public void RemoveSession(string userId)
 {
 sessions.TryRemove(userId, out _);
 }
 }
}