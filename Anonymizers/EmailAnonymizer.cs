using System.Text.RegularExpressions;
using FPE.Interfaces;
using static FPE.Constants.Constants;

namespace FPE.Anonymizers;

public class EmailAnonymizer : BaseAnonymizer
{
    private bool _preserveDomain;
    
    public EmailAnonymizer(IFF3Cipher cipher) : base(cipher)
    {
        _preserveDomain = true;
        SetPreserveCharacters(new[] { '@', '.' });
    }
    
    public void SetPreserveDomain(bool preserve)
    {
        _preserveDomain = preserve;
    }
    
    public override string Anonymize(string email)
    {
        var match = Regex.Match(email, Patterns.EmailPattern);
        
        if (!match.Success)
            return base.Anonymize(email);
            
        string username = match.Groups[1].Value;
        string domain = match.Groups[2].Value;
        
        string encryptedUsername = _cipher.WithCustomAlphabet(Alphabets.Email)
            .Encrypt(username);
            
        if (_preserveDomain)
            return encryptedUsername + "@" + domain;
            
        string encryptedDomain = _cipher.WithCustomAlphabet(Alphabets.Email)
            .Encrypt(domain);
            
        return encryptedUsername + "@" + encryptedDomain;
    }
    
    public override string Deanonymize(string anonymizedEmail)
    {
        var match = Regex.Match(anonymizedEmail, Patterns.EmailPattern);
        
        if (!match.Success)
            return base.Deanonymize(anonymizedEmail);
            
        string encryptedUsername = match.Groups[1].Value;
        string domain = match.Groups[2].Value;
        
        string decryptedUsername = _cipher.WithCustomAlphabet(Alphabets.Email)
            .Decrypt(encryptedUsername);
            
        if (_preserveDomain)
            return decryptedUsername + "@" + domain;
            
        string decryptedDomain = _cipher.WithCustomAlphabet(Alphabets.Email)
            .Decrypt(domain);
            
        return decryptedUsername + "@" + decryptedDomain;
    }
}