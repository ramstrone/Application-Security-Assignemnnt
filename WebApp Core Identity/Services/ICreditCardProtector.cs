namespace WebApp_Core_Identity.Services
{
 public interface ICreditCardProtector
 {
 string Protect(string plainText);
 string Unprotect(string protectedText);
 string Mask(string protectedText); // returns masked card e.g. **** **** ****1234
 }
}
