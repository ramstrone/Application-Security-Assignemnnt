using Microsoft.AspNetCore.DataProtection;
using System;

namespace WebApp_Core_Identity.Services
{
 public class CreditCardProtector : ICreditCardProtector
 {
 private readonly IDataProtector protector;
 public CreditCardProtector(IDataProtectionProvider provider)
 {
 protector = provider.CreateProtector("CreditCardProtector");
 }

 public string Protect(string plainText)
 {
 return protector.Protect(plainText);
 }

 public string Unprotect(string protectedText)
 {
 try
 {
 return protector.Unprotect(protectedText);
 }
 catch
 {
 return null;
 }
 }

 public string Mask(string protectedText)
 {
 var plain = Unprotect(protectedText);
 if (string.IsNullOrEmpty(plain) || plain.Length <4) return string.Empty;
 var last4 = plain.Substring(plain.Length -4);
 return "**** **** ****" + last4;
 }
 }
}
