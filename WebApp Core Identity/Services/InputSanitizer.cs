using System.Text.RegularExpressions;

namespace WebApp_Core_Identity.Services
{
 public static class InputSanitizer
 {
 // Very small sanitizer: removes HTML tags and script blocks and trims length
 public static string Sanitize(string input, int maxLength =1000)
 {
 if (string.IsNullOrEmpty(input)) return string.Empty;

 // Remove script/style blocks
 var noScripts = Regex.Replace(input, "<script[\\s\\S]*?>[\\s\\S]*?<\\/script>", string.Empty, RegexOptions.IgnoreCase);
 noScripts = Regex.Replace(noScripts, "<style[\\s\\S]*?>[\\s\\S]*?<\\/style>", string.Empty, RegexOptions.IgnoreCase);

 // Remove any remaining tags
 var noTags = Regex.Replace(noScripts, "<.*?>", string.Empty);

 // Collapse whitespace
 var collapsed = Regex.Replace(noTags, "\\s+", " ").Trim();

 if (collapsed.Length > maxLength)
 {
 return collapsed.Substring(0, maxLength);
 }

 return collapsed;
 }
 }
}
