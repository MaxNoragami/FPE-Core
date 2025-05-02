using FPE.Anonymizers;
using FPE.KeyManagement;
using FPE.Services;

Console.WriteLine("FF3-1 Format-Preserving Encryption Demo");
Console.WriteLine("---------------------------------------");

// Generate a key-tweak pair
var keyGen = new KeyGenerator();
var keyTweakPair = keyGen.GenerateKeyTweakPair("demo");

Console.WriteLine($"Generated Key: {keyTweakPair.Key}");
Console.WriteLine($"Generated Tweak: {BitConverter.ToString(keyTweakPair.Tweak).Replace("-", "")}");

// Create a cipher
var cipher = new FF3Cipher(keyTweakPair.Key, keyTweakPair.Tweak);

// Demo phone number anonymization
Console.WriteLine("\nPhone Number Anonymization:");
string phoneNumber = "+37369090275";
var phoneAnonymizer = new PhoneNumberAnonymizer(cipher);
phoneAnonymizer.SetPreserveCountryCode(true);
phoneAnonymizer.SetPreserveAreaCode(true);
string encryptedPhone = phoneAnonymizer.Anonymize(phoneNumber);
Console.WriteLine($"Original: {phoneNumber}");
Console.WriteLine($"Anonymized: {encryptedPhone}");

// Try decrypting to verify
string decryptedPhone = phoneAnonymizer.Deanonymize(encryptedPhone);
Console.WriteLine($"Decrypted: {decryptedPhone}");

// Demo email anonymization
Console.WriteLine("\nEmail Anonymization:");
string email = "maxim.alexei@isa.utm.md";
var emailAnonymizer = new EmailAnonymizer(cipher);
emailAnonymizer.SetPreserveDomain(true);
string encryptedEmail = emailAnonymizer.Anonymize(email);
Console.WriteLine($"Original: {email}");
Console.WriteLine($"Anonymized: {encryptedEmail}");

// Demo name anonymization
Console.WriteLine("\nName Anonymization:");
string name = "Name Surname";
var nameAnonymizer = new NameAnonymizer(cipher);
nameAnonymizer.SetPreserveCapitalization(true);
string encryptedName = nameAnonymizer.Anonymize(name);
Console.WriteLine($"Original: {name}");
Console.WriteLine($"Anonymized: {encryptedName}");

// Demo credit card anonymization
Console.WriteLine("\nCredit Card Anonymization:");
string creditCard = "5170 1705 8968 1828";
var ccAnonymizer = new CreditCardAnonymizer(cipher);
ccAnonymizer.SetPreserveFirstFour(true);
ccAnonymizer.SetPreserveLastFour(false);
string encryptedCC = ccAnonymizer.Anonymize(creditCard);
Console.WriteLine($"Original: {creditCard}");
Console.WriteLine($"Anonymized: {encryptedCC}");

// Wait for user input
Console.WriteLine("\nPress any key to exit...");
Console.ReadKey();