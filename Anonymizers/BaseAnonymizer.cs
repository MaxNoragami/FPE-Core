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
            
        // Encrypt the stripped string
        string encrypted = _cipher.Encrypt(stripped);
        
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
            
        string decrypted = _cipher.Decrypt(stripped);
        
        char[] result = decrypted.ToCharArray();
        int offset = 0;
        
        foreach (var position in preservePositions.OrderBy(p => p.Key))
        {
            result = result.Take(position.Key - offset)
                .Concat(new[] { position.Value })
                .Concat(result.Skip(position.Key - offset))
                .ToArray();
            offset++;
        }
        
        return new string(result);
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
                    // Encrypt this group
                    string encrypted = _cipher.Encrypt(group.Value);
                    
                    // Replace in the result
                    result = result.Substring(0, group.Index) + 
                                encrypted + 
                                result.Substring(group.Index + group.Length);
                }
            }
            
            return result;
        }
        
        return _cipher.Encrypt(input);
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
                    string decrypted = _cipher.Decrypt(group.Value);
                    
                    result = result.Substring(0, group.Index) + 
                                decrypted + 
                                result.Substring(group.Index + group.Length);
                }
            }
            
            return result;
        }
        
        return _cipher.Decrypt(input);
    }
}