SELECT UserName, Email, LockoutEnabled, LockoutEnd, AccessFailedCount
FROM AspNetUsers
WHERE Email = 'test@example.com';
SELECT SYSDATETIMEOFFSET() AS ServerNowUTCOffset;