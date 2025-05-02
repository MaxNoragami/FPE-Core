using FPE.Interfaces;

namespace FPE.Anonymizers;

public class StringAnonymizer : BaseAnonymizer
{
    public StringAnonymizer(IFF3Cipher cipher) : base(cipher)
    {
        // Basic string anonymizer with no special handling
    }
}