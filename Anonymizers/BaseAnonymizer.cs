using System.Text;
using System.Text.RegularExpressions;
using FPE.Interfaces;

namespace FPE.Anonymizers;

public abstract class BaseAnonymizer : IAnonymizer
{
    protected readonly IFF3Cipher _cipher;
    protected char[] _preserveChars;
    protected string _preservePattern;
    
    protected BaseAnonymizer(IFF3Cipher cipher)
    {
        _cipher = cipher;
        _preserveChars = new char[0];
        _preservePattern = string.Empty;
    }
    
    public virtual string Anonymize(string input)
    {
        // Apply pattern preservation if specified
        if (!string.IsNullOrEmpty(_preservePattern))
        {
            return AnonymizeWithPattern(input);
        }
        
        // Apply character preservation
        if (_preserveChars.Length > 0)
        {
            return AnonymizeWithPreservedChars(input);
        }
        
        // Basic anonymization
        return _cipher.Encrypt(input);
    }
    
    public virtual string Deanonymize(string input)
    {
        // Apply pattern preservation if specified
        if (!string.IsNullOrEmpty(_preservePattern))
        {
            return DeanonymizeWithPattern(input);
        }
        
        // Apply character preservation
        if (_preserveChars.Length > 0)
        {
            return DeanonymizeWithPreservedChars(input);
        }
        
        // Basic deanonymization
        return _cipher.Decrypt(input);
    }
    
    public void SetPreserveCharacters(char[] characters)
    {
        _preserveChars = characters;
    }
    
    public void SetPreservePattern(string pattern)
    {
        _preservePattern = pattern;
    }
    
    protected virtual string AnonymizeWithPreservedChars(string input)
    {
        // Store positions of preserved characters
        var preservePositions = input
            .Select((c, i) => new { Char = c, Index = i })
            .Where(x => _preserveChars.Contains(x.Char))
            .ToDictionary(x => x.Index, x => x.Char);
            
        // Remove preserved characters for encryption
        string stripped = new string(input
            .Where((c, i) => !preservePositions.ContainsKey(i))
            .ToArray());

        // If stripped is empty, nothing to encrypt
        if (string.IsNullOrEmpty(stripped))
            return input;
            
        // Check if string is too short (FF3 requires at least 2 characters)
        if (stripped.Length < 2)
            stripped = stripped.PadRight(2, 'A');
            
        // Create a custom alphabet that includes all characters in the stripped string
        string customAlphabet = CreateCustomAlphabet(stripped);
        
        // Encrypt the stripped string with the custom alphabet
        string encrypted;
        try
        {
            encrypted = _cipher.WithCustomAlphabet(customAlphabet).Encrypt(stripped);
        }
        catch (Exception)
        {
            // Fallback to base alphabet if custom fails
            stripped = MakeAlphabetSafe(stripped);
            encrypted = _cipher.Encrypt(stripped);
        }
        
        // Reinsert preserved characters
        char[] result = encrypted.ToCharArray();
        int offset = 0;
        
        foreach (var position in preservePositions.OrderBy(p => p.Key))
        {
            if (position.Key + offset < result.Length)
            {
                result = result.Take(position.Key + offset)
                    .Concat(new[] { position.Value })
                    .Concat(result.Skip(position.Key + offset))
                    .ToArray();
                offset++;
            }
            else
            {
                // Handle edge case where preserved char is at end
                result = result.Concat(new[] { position.Value }).ToArray();
            }
        }
        
        return new string(result);
    }

    protected virtual string DeanonymizeWithPreservedChars(string input)
    {
        // Similar to AnonymizeWithPreservedChars but in reverse
        var preservePositions = input
            .Select((c, i) => new { Char = c, Index = i })
            .Where(x => _preserveChars.Contains(x.Char))
            .ToDictionary(x => x.Index, x => x.Char);
            
        string stripped = new string(input
            .Where((c, i) => !preservePositions.ContainsKey(i))
            .ToArray());
            
        // If stripped is empty, nothing to decrypt
        if (string.IsNullOrEmpty(stripped))
            return input;
            
        // Check if string is too short
        if (stripped.Length < 2)
            return input;
        
        // Create a custom alphabet that includes all characters in the stripped string
        string customAlphabet = CreateCustomAlphabet(stripped);
        
        // Decrypt the stripped string with custom alphabet
        string decrypted;
        try
        {
            decrypted = _cipher.WithCustomAlphabet(customAlphabet).Decrypt(stripped);
        }
        catch (Exception)
        {
            // Fallback
            decrypted = _cipher.Decrypt(stripped);
        }
        
        char[] result = decrypted.ToCharArray();
        int offset = 0;
        
        foreach (var position in preservePositions.OrderBy(p => p.Key))
        {
            if (position.Key - offset >= 0 && position.Key - offset <= result.Length)
            {
                result = result.Take(position.Key - offset)
                    .Concat(new[] { position.Value })
                    .Concat(result.Skip(position.Key - offset))
                    .ToArray();
                offset--;
            }
            else
            {
                // Handle edge case
                result = (new[] { position.Value }).Concat(result).ToArray();
            }
        }
        
        return new string(result);
    }

    // Add these helper methods to the BaseAnonymizer class
    private string CreateCustomAlphabet(string text)
    {
        // Create a custom alphabet containing unique characters from the text
        // plus standard alphanumeric characters to ensure it's compatible with FF3
        HashSet<char> uniqueChars = new HashSet<char>(text);
        
        // Make sure we have all basic alphanumeric characters
        foreach (char c in Constants.Constants.Alphabets.AlphaNumeric)
        {
            uniqueChars.Add(c);
        }
        
        return new string(uniqueChars.ToArray());
    }

    protected virtual string AnonymizeWithPattern(string input)
    {
        // Implement regex-based pattern preservation
        var regex = new Regex(_preservePattern);
        var match = regex.Match(input);
        
        if (match.Success)
        {
            string result = input;
            
            // For each capturing group
            for (int i = 1; i < match.Groups.Count; i++)
            {
                var group = match.Groups[i];
                if (group.Success)
                {
                    // Get the value to encrypt
                    string valueToEncrypt = group.Value;
                    
                    // Skip empty groups
                    if (string.IsNullOrEmpty(valueToEncrypt))
                        continue;
                    
                    // Ensure minimum length for FF3
                    if (valueToEncrypt.Length < 2)
                        valueToEncrypt = valueToEncrypt.PadRight(2, 'X');
                    
                    // Create a custom alphabet for this value
                    string customAlphabet = CreateCustomAlphabetForValue(valueToEncrypt);
                    
                    // Encrypt this group
                    string encrypted;
                    try 
                    {
                        // Try with custom alphabet first
                        encrypted = _cipher.WithCustomAlphabet(customAlphabet).Encrypt(valueToEncrypt);
                    }
                    catch (Exception)
                    {
                        // Fallback to safe encryption
                        string safeValue = MakeAlphabetSafe(valueToEncrypt);
                        encrypted = _cipher.Encrypt(safeValue);
                    }
                    
                    // Replace in the result
                    result = result.Substring(0, group.Index) + 
                                encrypted + 
                                result.Substring(group.Index + group.Length);
                }
            }
            
            return result;
        }
        
        // If no pattern match, try encrypting the whole string
        try
        {
            // Create a custom alphabet for the entire input
            string customAlphabet = CreateCustomAlphabetForValue(input);
            return _cipher.WithCustomAlphabet(customAlphabet).Encrypt(input);
        }
        catch
        {
            // Fallback to safe encryption
            string safeInput = MakeAlphabetSafe(input);
            return _cipher.Encrypt(safeInput);
        }
    }

    protected virtual string DeanonymizeWithPattern(string input)
    {
        // Similar to AnonymizeWithPattern but using decrypt
        var regex = new Regex(_preservePattern);
        var match = regex.Match(input);
        
        if (match.Success)
        {
            string result = input;
            
            for (int i = 1; i < match.Groups.Count; i++)
            {
                var group = match.Groups[i];
                if (group.Success)
                {
                    // Get the value to decrypt
                    string valueToDecrypt = group.Value;
                    
                    // Skip empty groups
                    if (string.IsNullOrEmpty(valueToDecrypt))
                        continue;
                    
                    // Create a custom alphabet for this value
                    string customAlphabet = CreateCustomAlphabetForValue(valueToDecrypt);
                    
                    // Decrypt this group
                    string decrypted;
                    try 
                    {
                        // Try with custom alphabet first
                        decrypted = _cipher.WithCustomAlphabet(customAlphabet).Decrypt(valueToDecrypt);
                    }
                    catch (Exception)
                    {
                        // Fallback to default decryption
                        try
                        {
                            decrypted = _cipher.Decrypt(valueToDecrypt);
                        }
                        catch
                        {
                            // If all else fails, return as is
                            decrypted = valueToDecrypt;
                        }
                    }
                    
                    // Replace in the result
                    result = result.Substring(0, group.Index) + 
                                decrypted + 
                                result.Substring(group.Index + group.Length);
                }
            }
            
            return result;
        }
        
        // If no pattern match, try decrypting the whole string
        try
        {
            // Create a custom alphabet for the entire input
            string customAlphabet = CreateCustomAlphabetForValue(input);
            return _cipher.WithCustomAlphabet(customAlphabet).Decrypt(input);
        }
        catch
        {
            // Fallback to default decryption
            try
            {
                return _cipher.Decrypt(input);
            }
            catch
            {
                // If all else fails, return as is
                return input;
            }
        }
    }

    // Helper method specifically for creating pattern-appropriate alphabets
    private string CreateCustomAlphabetForValue(string value)
    {
        // Include all characters in the value plus standard alphanumeric characters
        HashSet<char> chars = new HashSet<char>();
        
        // Add all characters from the value
        foreach (char c in value)
        {
            chars.Add(c);
        }
        
        // Add standard alphanumeric characters to ensure it works properly
        foreach (char c in Constants.Constants.Alphabets.AlphaNumeric)
        {
            chars.Add(c);
        }
        
        // Add some common special characters that might appear in patterns
        string specialChars = "-.,;:_+=!@#$%^&*()[]{}|<>/\\\"'";
        foreach (char c in specialChars)
        {
            chars.Add(c);
        }
        
        // Convert to string and return
        return new string(chars.ToArray());
    }

    // Method to make strings safe for the default alphabet
    private string MakeAlphabetSafe(string input)
    {
        // Filter out or replace characters not in the default alphabet
        string safeAlphabet = Constants.Constants.Alphabets.AlphaNumeric;
        StringBuilder result = new StringBuilder();
        
        foreach (char c in input)
        {
            if (safeAlphabet.Contains(c))
            {
                result.Append(c);
            }
            else
            {
                // Replace with a safe character
                result.Append('X');
            }
        }
        
        // Ensure minimum length
        if (result.Length < 2)
        {
            result.Append("XX");
        }
        
        return result.ToString();
    }
}