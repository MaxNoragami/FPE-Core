using FPE.Interfaces;
using static FPE.Constants.Constants;

namespace FPE.Anonymizers;

public class NameAnonymizer : BaseAnonymizer
{
    private bool _preserveCapitalization;
    
    public NameAnonymizer(IFF3Cipher cipher) : base(cipher)
    {
        _preserveCapitalization = true;
    }
    
    public void SetPreserveCapitalization(bool preserve)
    {
        _preserveCapitalization = preserve;
    }
    
    public override string Anonymize(string name)
    {
        if (string.IsNullOrEmpty(name))
            return name;
            
        // Handle spaces in names
        if (name.Contains(" "))
        {
            string[] parts = name.Split(' ');
            for (int i = 0; i < parts.Length; i++)
            {
                parts[i] = AnonymizeSingleName(parts[i]);
            }
            return string.Join(" ", parts);
        }
        
        return AnonymizeSingleName(name);
    }
    
    private string AnonymizeSingleName(string name)
    {
        if (string.IsNullOrEmpty(name))
            return name;
            
        bool isCapitalized = char.IsUpper(name[0]);
        
        // Convert to lowercase for consistent encryption
        string lowerName = name.ToLower();
        
        // Use a consistent alphabet for names
        string encrypted = _cipher.WithCustomAlphabet(Alphabets.LowerAlpha)
            .Encrypt(lowerName);
            
        // Restore capitalization if needed
        if (_preserveCapitalization && isCapitalized && encrypted.Length > 0)
        {
            return char.ToUpper(encrypted[0]) + encrypted.Substring(1);
        }
        
        return encrypted;
    }
    
    public override string Deanonymize(string anonymizedName)
    {
        if (string.IsNullOrEmpty(anonymizedName))
            return anonymizedName;
            
        if (anonymizedName.Contains(" "))
        {
            string[] parts = anonymizedName.Split(' ');
            for (int i = 0; i < parts.Length; i++)
            {
                parts[i] = DeanonymizeSingleName(parts[i]);
            }
            return string.Join(" ", parts);
        }
        
        return DeanonymizeSingleName(anonymizedName);
    }
    
    private string DeanonymizeSingleName(string name)
    {
        if (string.IsNullOrEmpty(name))
            return name;
            
        bool isCapitalized = char.IsUpper(name[0]);
        
        string lowerName = name.ToLower();
        
        string decrypted = _cipher.WithCustomAlphabet(Alphabets.LowerAlpha)
            .Decrypt(lowerName);
            
        if (_preserveCapitalization && isCapitalized && decrypted.Length > 0)
        {
            return char.ToUpper(decrypted[0]) + decrypted.Substring(1);
        }
        
        return decrypted;
    }
}