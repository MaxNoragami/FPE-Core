using FPE.Interfaces;
using static FPE.Constants.Constants;

namespace FPE.Anonymizers;

public class NumberStringAnonymizer : BaseAnonymizer
{
    public NumberStringAnonymizer(IFF3Cipher cipher) : base(cipher)
    {
        // Basic numeric string anonymizer
    }
    
    public override string Anonymize(string input)
    {
        // Ensure we're only dealing with digits
        foreach (char c in input)
        {
            if (!Alphabets.Digits.Contains(c))
                throw new ArgumentException("Input contains non-digit characters");
        }
        
        return base.Anonymize(input);
    }
}