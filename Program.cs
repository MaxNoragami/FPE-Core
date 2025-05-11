using FPE.Anonymizers;
using FPE.Constants;
using FPE.KeyManagement;
using FPE.Services;

Console.WriteLine("FF3-1 Format-Preserving Encryption Demo");
Console.WriteLine("---------------------------------------");

// Generate a key-tweak pair
var keyGen = new KeyGenerator();
var keyTweakPair = keyGen.GenerateKeyTweakPair("demo");

Console.WriteLine($"Generated Key: {keyTweakPair.Key}");


// Create a cipher
var cipher = new FF3Cipher(keyTweakPair.Key, keyTweakPair.Tweak);
//var cipher = new FF3Cipher(keyTweakPair.Key, Constants.Tweaks.DefaultTweak);

Console.WriteLine($"Generated Tweak: {BitConverter.ToString(keyTweakPair.Tweak).Replace("-", "")}");
Console.WriteLine($"Constant Tweak: {BitConverter.ToString(Constants.Tweaks.DefaultTweak).Replace("-", "")}");

// Demo phone number anonymization
Console.WriteLine("\nPhone Number Anonymization:");
string phoneNumber = "+1 415 5550198";
var phoneAnonymizer = new PhoneNumberAnonymizer(cipher);
var phoneDeanonymizer = new PhoneNumberAnonymizer(cipher);
phoneAnonymizer.SetPreserveCountryCode(true);
phoneAnonymizer.SetPreserveAreaCode(true);
phoneDeanonymizer.SetPreserveCountryCode(true);
phoneDeanonymizer.SetPreserveAreaCode(true);
string encryptedPhone = phoneAnonymizer.Anonymize(phoneNumber);
Console.WriteLine($"Original: {phoneNumber}");
Console.WriteLine($"Anonymized: {encryptedPhone}");

// Try decrypting to verify
string decryptedPhone = phoneDeanonymizer.Deanonymize(encryptedPhone);
Console.WriteLine($"Deanonymized: {decryptedPhone}");

// Add the following to Program.cs to test our enhanced anonymizers

// Test NameAnonymizer with special characters
Console.WriteLine("\nName Anonymization with Special Characters:");
string specialName = "Global Dataîâbașse SR.-L";
var specialNameAnonymizer = new NameAnonymizer(cipher);
var specialNameDeanonymizer = new NameAnonymizer(cipher);
specialNameAnonymizer.SetPreserveCapitalization(true);
specialNameAnonymizer.SetPreserveSpecialChars(false); // Will encrypt special chars

specialNameDeanonymizer.SetPreserveCapitalization(true);
specialNameDeanonymizer.SetPreserveSpecialChars(false);

string encryptedSpecialName = specialNameAnonymizer.Anonymize(specialName);
string decryptedSpecialName = specialNameDeanonymizer.Deanonymize(encryptedSpecialName);

Console.WriteLine($"Original: {specialName}");
Console.WriteLine($"Anonymized: {encryptedSpecialName}");
Console.WriteLine($"Deanonymized: {decryptedSpecialName}");

// Now with preserved special chars
specialNameAnonymizer.SetPreserveSpecialChars(true);
specialNameDeanonymizer.SetPreserveSpecialChars(true);
string encryptedSpecialName2 = specialNameAnonymizer.Anonymize(specialName);
string decryptedSpecialName2 = specialNameDeanonymizer.Deanonymize(encryptedSpecialName2);

Console.WriteLine($"\nWith preserved special chars:");
Console.WriteLine($"Original: {specialName}");
Console.WriteLine($"Anonymized: {encryptedSpecialName2}");
Console.WriteLine($"Deanonymized: {decryptedSpecialName2}");

// Test EmailAnonymizer with dots and underscores
Console.WriteLine("\nEmail Anonymization with Special Characters:");
string specialEmail = "john.doe_test@example.com";
var specialEmailAnonymizer = new EmailAnonymizer(cipher);
var specialEmailDeanonymizer = new EmailAnonymizer(cipher);
specialEmailAnonymizer.SetPreserveDomain(true);
specialEmailAnonymizer.SetPreserveDots(true);
specialEmailAnonymizer.SetPreserveUnderscores(true);

specialEmailDeanonymizer.SetPreserveDomain(true);
specialEmailDeanonymizer.SetPreserveDots(true);
specialEmailDeanonymizer.SetPreserveUnderscores(true);

string encryptedSpecialEmail = specialEmailAnonymizer.Anonymize(specialEmail);
string decryptedSpecialEmail = specialEmailDeanonymizer.Deanonymize(encryptedSpecialEmail);

Console.WriteLine($"Original: {specialEmail}");
Console.WriteLine($"Anonymized (preserving dots and underscores): {encryptedSpecialEmail}");
Console.WriteLine($"Deanonymized: {decryptedSpecialEmail}");

// Without preserving special chars
specialEmailAnonymizer.SetPreserveDots(false);
specialEmailAnonymizer.SetPreserveUnderscores(false);

specialEmailDeanonymizer.SetPreserveDots(false);
specialEmailDeanonymizer.SetPreserveUnderscores(false);

string encryptedSpecialEmail2 = specialEmailAnonymizer.Anonymize(specialEmail);
string decryptedSpecialEmail2 = specialEmailDeanonymizer.Deanonymize(encryptedSpecialEmail2);

Console.WriteLine($"\nWithout preserving dots and underscores:");
Console.WriteLine($"Original: {specialEmail}");
Console.WriteLine($"Anonymized: {encryptedSpecialEmail2}");
Console.WriteLine($"Deanonymized: {decryptedSpecialEmail2}");

// Demo credit card anonymization
Console.WriteLine("\nCredit Card Anonymization:");
string creditCard = "5170 1705 8968 1828";
var ccAnonymizer = new CreditCardAnonymizer(cipher);
var ccDeanonymizer = new CreditCardAnonymizer(cipher);
ccAnonymizer.SetPreserveFirstFour(true);
ccAnonymizer.SetPreserveLastFour(false);

ccDeanonymizer.SetPreserveFirstFour(true);
ccDeanonymizer.SetPreserveLastFour(false);
string encryptedCC = ccAnonymizer.Anonymize(creditCard);
Console.WriteLine($"Original: {creditCard}");
Console.WriteLine($"Anonymized: {encryptedCC}");
string decryptedCC = ccDeanonymizer.Deanonymize(encryptedCC);
Console.WriteLine($"Deanonymized: {decryptedCC}");

// Demo enhanced string anonymization
Console.WriteLine("\nEnhanced String Anonymization:");
string text = "This example with Romănă chars.";  // Shortened example
var strAnonymizer = new StringAnonymizer(cipher);
var strDeanonymizer = new StringAnonymizer(cipher);
strAnonymizer.SetPreserveCase(true);
strAnonymizer.SetPreserveSpaces(true);
strAnonymizer.SetPreservePunctuation(true);

strDeanonymizer.SetPreserveCase(true);
strDeanonymizer.SetPreserveSpaces(true);
strDeanonymizer.SetPreservePunctuation(true);
string encryptedText = strAnonymizer.Anonymize(text);
Console.WriteLine($"Original: {text}");
Console.WriteLine($"Anonymized: {encryptedText}");
string decryptedText = strDeanonymizer.Deanonymize(encryptedText);
Console.WriteLine($"Deanonymized: {decryptedText}");

// Now test longer text
Console.WriteLine("\nLong Text Anonymization:");
string longText = "This is a much longer example of text that would normally exceed the FF3-1 algorithm's limits. It contains special characters like €$%&@!? and multiple sentences.";
string encryptedLongText = strAnonymizer.Anonymize(longText);
Console.WriteLine($"Original: {longText}");
Console.WriteLine($"Anonymized: {encryptedLongText}");
string decryptedLongText = strDeanonymizer.Deanonymize(encryptedLongText);
Console.WriteLine($"Deanonymized: {decryptedLongText}");

// Demo numeric anonymization
Console.WriteLine("\nNumeric Anonymization:");
string number = "-12345.6789";
var numAnonymizer = new NumericAnonymizer(cipher);
var numDeanonymizer = new NumericAnonymizer(cipher);
numAnonymizer.SetPreserveSign(true);
numAnonymizer.SetPreserveDecimalPoint(true);
numAnonymizer.SetPreserveDecimalPlaces(2);

numDeanonymizer.SetPreserveSign(true);
numDeanonymizer.SetPreserveDecimalPoint(true);
numDeanonymizer.SetPreserveDecimalPlaces(2);
string encryptedNumber = numAnonymizer.Anonymize(number);
Console.WriteLine($"Original: {number}");
Console.WriteLine($"Anonymized: {encryptedNumber}");
string decryptedNumber = numDeanonymizer.Deanonymize(encryptedNumber);
Console.WriteLine($"Deanonymized: {decryptedNumber}");

// Demo date anonymization
Console.WriteLine("\nDate Anonymization:");
string date = "2024-05-11";
var dateAnonymizer = new DateAnonymizer(cipher);
var dateDeanonymizer = new DateAnonymizer(cipher);
dateAnonymizer.SetPreserveYear(true);
dateAnonymizer.SetPreserveMonth(false);
dateAnonymizer.SetPreserveDay(false);
dateAnonymizer.SetDateFormat("yyyy-MM-dd");

dateDeanonymizer.SetPreserveYear(true);
dateDeanonymizer.SetPreserveMonth(false);
dateDeanonymizer.SetPreserveDay(false);
dateDeanonymizer.SetDateFormat("yyyy-MM-dd");
string encryptedDate = dateAnonymizer.Anonymize(date);
Console.WriteLine($"Original: {date}");
Console.WriteLine($"Anonymized: {encryptedDate}");
string decryptedDate = dateDeanonymizer.Deanonymize(encryptedDate);
Console.WriteLine($"Deanonymized: {decryptedDate}");

// Test different date format
Console.WriteLine("\nDate Format Variations:");
string dateWithFormat = "11/05/2024";
var dateFormatAnonymizer = new DateAnonymizer(cipher);
var dateFormatDenonymizer = new DateAnonymizer(cipher);
dateFormatAnonymizer.SetPreserveYear(true);
dateFormatAnonymizer.SetPreserveMonth(false);
dateFormatAnonymizer.SetPreserveDay(false);
dateFormatAnonymizer.SetDateFormat("dd/MM/yyyy");

dateFormatDenonymizer.SetPreserveYear(true);
dateFormatDenonymizer.SetPreserveMonth(false);
dateFormatDenonymizer.SetPreserveDay(false);
dateFormatDenonymizer.SetDateFormat("dd/MM/yyyy");
string encryptedDateFormat = dateFormatAnonymizer.Anonymize(dateWithFormat);
Console.WriteLine($"Original: {dateWithFormat}");
Console.WriteLine($"Anonymized: {encryptedDateFormat}");
string decryptedDateFormat = dateFormatDenonymizer.Deanonymize(encryptedDateFormat);
Console.WriteLine($"Deanonymized: {decryptedDateFormat}");

// Test with different settings for each anonymizer
Console.WriteLine("\nVariation Tests:");

// String with different settings
Console.WriteLine("\nString without preserving spaces and punctuation:");
var strVariationAnonymizer = new StringAnonymizer(cipher);
var strVariationDeanonymizer = new StringAnonymizer(cipher);

string encryptedTextVar = strVariationAnonymizer.Anonymize(text);
Console.WriteLine($"Original: {text}");
Console.WriteLine($"Anonymized: {encryptedTextVar}");
string decryptedTextVar = strVariationDeanonymizer.Deanonymize(encryptedTextVar);
Console.WriteLine($"Deanonymized: {decryptedTextVar}");

// Numeric with different settings
Console.WriteLine("\nNumeric without preserving decimals:");
var numVariationAnonymizer = new NumericAnonymizer(cipher);
var numVariationDeanonymizer = new NumericAnonymizer(cipher);
numVariationAnonymizer.SetPreserveSign(true);
numVariationAnonymizer.SetPreserveDecimalPoint(false);
numVariationDeanonymizer.SetPreserveSign(true);
numVariationDeanonymizer.SetPreserveDecimalPoint(false);
string encryptedNumberVar = numVariationAnonymizer.Anonymize(number);
Console.WriteLine($"Original: {number}");
Console.WriteLine($"Anonymized: {encryptedNumberVar}");
string decryptedNumberVar = numVariationDeanonymizer.Deanonymize(encryptedNumberVar);
Console.WriteLine($"Deanonymized: {decryptedNumberVar}");

Console.WriteLine("\nString Anonymizer with Various Character Sets:");
string[] testStrings = new string[] 
{
    "Basic ASCII text",
    "Romanian: ă î â ș ț Ă Î Â Ș Ț",
    "Symbols: €£¥§©®™ !@#$%^&*()",
    "Mixed 12345 with numbers and symbols !@#",
    "A longer text with multiple words and sentences. This tests how well it works.",
    "A longer text with multiple words and sentences. This tests how well it works."
};

foreach (var testStr in testStrings)
{
    var strTester = new StringAnonymizer(cipher);
    var strTesterDeanonym = new StringAnonymizer(cipher);
    
    string encrypted = strTester.Anonymize(testStr);
    string decrypted = strTesterDeanonym.Deanonymize(encrypted);
    
    Console.WriteLine($"Original: {testStr}");
    Console.WriteLine($"Anonymized: {encrypted}");
    Console.WriteLine($"Deanonymized: {decrypted}");
    Console.WriteLine($"Match: {testStr == decrypted}");
    Console.WriteLine();
}

/// Demo address anonymization
Console.WriteLine("\nAddress Anonymization:");
string[] addresses = new string[] 
{
    "bd. Ștefan cel Mare și Sfânt, 134, MD-2012, mun. Chișinău, Moldova",
    "Stefan cel Mare si Sfant Boulevard 8, MD-2001",
    "Strada Trei Scaune nr.29, Bucuresti 2, 021211",
    "65 Ponteland Rd",
    "2084 Swick Hill Street2084 Swick Hill Street2084 Swick Hill Street",
};

Console.WriteLine("Using StringAnonymizer for addresses:");
var addressStrAnonymizer = new StringAnonymizer(cipher);
var addressStrDeanonymizer = new StringAnonymizer(cipher);


Console.WriteLine("\nDefault settings (preserve case, spaces, and punctuation):");
foreach (var address in addresses)
{
    string anonymized = addressStrAnonymizer.Anonymize(address);
    string deanonymized = addressStrDeanonymizer.Deanonymize(anonymized);
    
    Console.WriteLine($"Original: {address}");
    Console.WriteLine($"Anonymized: {anonymized}");
    Console.WriteLine($"Deanonymized: {deanonymized}");
    Console.WriteLine();
}

// If you want to preserve some specific characters like postal code formats
var addressStrAnonymizer2 = new StringAnonymizer(cipher);
var addressStrDeanonymizer2 = new StringAnonymizer(cipher);


Console.WriteLine("\nAlternative settings (also preserving digits and hyphens):");
foreach (var address in addresses)
{
    string anonymized = addressStrAnonymizer2.Anonymize(address);
    string deanonymized = addressStrDeanonymizer2.Deanonymize(anonymized);
    
    Console.WriteLine($"Original: {address}");
    Console.WriteLine($"Anonymized: {anonymized}");
    Console.WriteLine($"Deanonymized: {deanonymized}");
    Console.WriteLine();
}


// Wait for user input
Console.WriteLine("\nPress any key to exit...");
Console.ReadKey();