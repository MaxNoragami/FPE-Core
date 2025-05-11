using System.Text.RegularExpressions;
using FPE.Interfaces;
using static FPE.Constants.Constants;

namespace FPE.Anonymizers;

public class EmailAnonymizer : BaseAnonymizer
{
    private bool _preserveDomain;
    private bool _preserveDots;
    private bool _preserveUnderscores;
    
    public EmailAnonymizer(IFF3Cipher cipher) : base(cipher)
    {
        _preserveDomain = true;
        _preserveDots = false;
        _preserveUnderscores = false;
        
        // Only preserve @ by default
        SetPreserveCharacters(new[] { '@' });
    }
    
    public void SetPreserveDomain(bool preserve)
    {
        _preserveDomain = preserve;
    }
    
    public void SetPreserveDots(bool preserve)
    {
        _preserveDots = preserve;
        UpdatePreservedChars();
    }
    
    public void SetPreserveUnderscores(bool preserve)
    {
        _preserveUnderscores = preserve;
        UpdatePreservedChars();
    }
    
    private void UpdatePreservedChars()
    {
        var chars = new List<char> { '@' };
        
        if (_preserveDots)
            chars.Add('.');
            
        if (_preserveUnderscores)
            chars.Add('_');
            
        SetPreserveCharacters(chars.ToArray());
    }
    
    public override string Anonymize(string email)
    {
        var match = Regex.Match(email, Patterns.EmailPattern);
        
        if (!match.Success)
            return base.Anonymize(email);
            
        string username = match.Groups[1].Value;
        string domain = match.Groups[2].Value;
        
        // Handle username part with preserved characters
        string encryptedUsername;
        
        if (_preserveDots || _preserveUnderscores)
        {
            // Create a char array to track positions of characters we want to preserve
            char[] usernameChars = username.ToCharArray();
            List<int> preservedPositions = new List<int>();
            
            // Find positions of characters to preserve
            for (int i = 0; i < usernameChars.Length; i++)
            {
                if ((_preserveDots && usernameChars[i] == '.') || 
                    (_preserveUnderscores && usernameChars[i] == '_'))
                {
                    preservedPositions.Add(i);
                }
            }
            
            if (preservedPositions.Count > 0)
            {
                // Create a version without preserved characters
                string stripUsername = "";
                for (int i = 0; i < username.Length; i++)
                {
                    if (!preservedPositions.Contains(i))
                    {
                        stripUsername += username[i];
                    }
                }
                
                // Ensure we have at least 2 characters (FF3 requirement)
                if (stripUsername.Length < 2)
                {
                    stripUsername = stripUsername.PadRight(2, 'a');
                }
                
                // Encrypt the stripped version
                string encryptedStrip = _cipher.WithCustomAlphabet(Alphabets.Email).Encrypt(stripUsername);
                
                // Rebuild the username with preserved characters
                char[] result = new char[username.Length];
                int encryptedIndex = 0;
                
                for (int i = 0; i < username.Length; i++)
                {
                    if (preservedPositions.Contains(i))
                    {
                        result[i] = username[i]; // Preserved character
                    }
                    else if (encryptedIndex < encryptedStrip.Length)
                    {
                        result[i] = encryptedStrip[encryptedIndex++]; // Encrypted character
                    }
                    else
                    {
                        // In case encrypted text is shorter
                        result[i] = 'x';
                    }
                }
                
                encryptedUsername = new string(result);
            }
            else
            {
                // No characters to preserve, encrypt normally
                encryptedUsername = _cipher.WithCustomAlphabet(Alphabets.Email).Encrypt(username);
            }
        }
        else
        {
            // If not preserving special chars, encrypt normally
            encryptedUsername = _cipher.WithCustomAlphabet(Alphabets.Email).Encrypt(username);
        }
        
        // Handle domain part
        if (_preserveDomain)
            return encryptedUsername + "@" + domain;
            
        string encryptedDomain = _cipher.WithCustomAlphabet(Alphabets.Email).Encrypt(domain);
        return encryptedUsername + "@" + encryptedDomain;
    }
    
    public override string Deanonymize(string anonymizedEmail)
    {
        var match = Regex.Match(anonymizedEmail, Patterns.EmailPattern);
        
        if (!match.Success)
            return base.Deanonymize(anonymizedEmail);
            
        string encryptedUsername = match.Groups[1].Value;
        string domain = match.Groups[2].Value;
        
        // Handle username part with preserved characters
        string decryptedUsername;
        
        if (_preserveDots || _preserveUnderscores)
        {
            // Create a char array to track positions of characters we want to preserve
            char[] usernameChars = encryptedUsername.ToCharArray();
            List<int> preservedPositions = new List<int>();
            
            // Find positions of characters to preserve
            for (int i = 0; i < usernameChars.Length; i++)
            {
                if ((_preserveDots && usernameChars[i] == '.') || 
                    (_preserveUnderscores && usernameChars[i] == '_'))
                {
                    preservedPositions.Add(i);
                }
            }
            
            if (preservedPositions.Count > 0)
            {
                // Create a version without preserved characters
                string stripUsername = "";
                for (int i = 0; i < encryptedUsername.Length; i++)
                {
                    if (!preservedPositions.Contains(i))
                    {
                        stripUsername += encryptedUsername[i];
                    }
                }
                
                // Ensure we have at least 2 characters (FF3 requirement)
                if (stripUsername.Length < 2)
                {
                    stripUsername = stripUsername.PadRight(2, 'a');
                }
                
                // Decrypt the stripped version
                string decryptedStrip = _cipher.WithCustomAlphabet(Alphabets.Email).Decrypt(stripUsername);
                
                // Rebuild the username with preserved characters
                char[] result = new char[encryptedUsername.Length];
                int decryptedIndex = 0;
                
                for (int i = 0; i < encryptedUsername.Length; i++)
                {
                    if (preservedPositions.Contains(i))
                    {
                        result[i] = encryptedUsername[i]; // Preserved character
                    }
                    else if (decryptedIndex < decryptedStrip.Length)
                    {
                        result[i] = decryptedStrip[decryptedIndex++]; // Decrypted character
                    }
                    else
                    {
                        // In case decrypted text is shorter
                        result[i] = 'x';
                    }
                }
                
                decryptedUsername = new string(result);
            }
            else
            {
                // No characters to preserve, decrypt normally
                decryptedUsername = _cipher.WithCustomAlphabet(Alphabets.Email).Decrypt(encryptedUsername);
            }
        }
        else
        {
            // If not preserving special chars, decrypt normally
            decryptedUsername = _cipher.WithCustomAlphabet(Alphabets.Email).Decrypt(encryptedUsername);
        }
        
        // Handle domain part
        if (_preserveDomain)
            return decryptedUsername + "@" + domain;
            
        string decryptedDomain = _cipher.WithCustomAlphabet(Alphabets.Email).Decrypt(domain);
        return decryptedUsername + "@" + decryptedDomain;
    }
}