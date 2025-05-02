using FPE.Interfaces;

namespace FPE.Anonymizers;

public class PersonalIdentifierAnonymizer : BaseAnonymizer
    {
        public PersonalIdentifierAnonymizer(IFF3Cipher cipher) : base(cipher)
        {
        }
        
        // This anonymizer can be configured to work with different formats of IDs
        // by setting appropriate preservation patterns or characters
        
        // Example for Romanian CNP format: yymmddcccrrrs
        public void ConfigureForRomanianCNP()
        {
            // Preserve the first 6 digits (birth date)
            SetPreservePattern(@"^(\d{6})(\d{7})$");
        }
        
        // Example for Social Security Number (SSN)
        public void ConfigureForSSN()
        {
            // Common pattern is to preserve only the last 4 digits
            SetPreservePattern(@"^(\d{5})(\d{4})$");
        }
        
        // Can add more specific ID formats as needed
    }