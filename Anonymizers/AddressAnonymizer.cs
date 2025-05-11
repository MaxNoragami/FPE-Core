using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using FPE.Interfaces;
using static FPE.Constants.Constants;

namespace FPE.Anonymizers;

public class AddressAnonymizer : BaseAnonymizer
{
    private bool _preservePostalCode;
    private bool _preserveCountry;
    private bool _preserveCity;
    private bool _preserveStreetNumber;
    private bool _preserveStreetPrefix;
    private bool _preserveStreetSuffix;
    
    // For tracking original-to-anonymized mappings
    private Dictionary<string, string> _originalToAnonymized;
    private Dictionary<string, string> _anonymizedToOriginal;
    
    // Child anonymizers
    private StringAnonymizer _textAnonymizer;
    private NumericAnonymizer _numericAnonymizer;
    
    // Constants for address part detection
    private static readonly string[] STREET_PREFIXES = { 
        "bd.", "blvd.", "str.", "strada", "avenue", "ave.", "boulevard",
        "st.", "ln.", "lane", "road", "rd.", "drive", "dr.", "place", "pl.",
        "alley", "court", "ct." 
    };
    
    private static readonly string[] COUNTRY_NAMES = {
        "Moldova", "Romania", "USA", "UK", "United States", "United Kingdom",
        "Ukraine", "Russia", "France", "Germany", "Italy", "Spain"
    };
    
    // Common postal code patterns for different countries
    private static readonly Regex POSTAL_CODE_PATTERN = new Regex(
        @"\b([A-Z]{1,2}[-\s]?\d{1,5}|\d{4,6}|MD[-\s]?\d{4})\b");
    
    // Street number patterns
    private static readonly Regex STREET_NUMBER_PATTERN = new Regex(
        @"\b(\d+[A-Za-z]?)\b|nr\.?(\d+)");
    
    public AddressAnonymizer(IFF3Cipher cipher) : base(cipher)
    {
        _preservePostalCode = true;
        _preserveCountry = true;
        _preserveCity = false;
        _preserveStreetNumber = false;
        _preserveStreetPrefix = true;
        _preserveStreetSuffix = true;
        
        _originalToAnonymized = new Dictionary<string, string>();
        _anonymizedToOriginal = new Dictionary<string, string>();
        
        // Initialize anonymizers
        _textAnonymizer = new StringAnonymizer(cipher);
        _textAnonymizer.SetPreserveCase(true);
        _textAnonymizer.SetPreserveSpaces(true);
        _textAnonymizer.SetPreservePunctuation(true);
        
        _numericAnonymizer = new NumericAnonymizer(cipher);
        _numericAnonymizer.SetPreserveSign(true);
    }
    
    // Configuration methods
    public void SetPreservePostalCode(bool preserve) => _preservePostalCode = preserve;
    public void SetPreserveCountry(bool preserve) => _preserveCountry = preserve;
    public void SetPreserveCity(bool preserve) => _preserveCity = preserve;
    public void SetPreserveStreetNumber(bool preserve) => _preserveStreetNumber = preserve;
    public void SetPreserveStreetPrefix(bool preserve) => _preserveStreetPrefix = preserve;
    public void SetPreserveStreetSuffix(bool preserve) => _preserveStreetSuffix = preserve;
    
    public override string Anonymize(string address)
    {
        if (string.IsNullOrEmpty(address))
            return address;
            
        // Check for cached result
        if (_originalToAnonymized.TryGetValue(address, out string existingAnonymized))
            return existingAnonymized;
            
        // Parse the address into components
        AddressComponents components = ParseAddress(address);
        
        // Build a working copy
        string result = address;
        
        // Process each identified component
        
        // 1. Street name
        if (!string.IsNullOrEmpty(components.StreetName))
        {
            string anonymizedStreetName = _textAnonymizer.Anonymize(components.StreetName);
            result = SafeReplace(result, components.StreetName, anonymizedStreetName);
        }
        
        // 2. Street number
        if (!string.IsNullOrEmpty(components.StreetNumber) && !_preserveStreetNumber)
        {
            string anonymizedNumber;
            
            // Handle minimum length requirement for FF3
            if (components.StreetNumber.Length < 2)
            {
                anonymizedNumber = _numericAnonymizer.Anonymize(components.StreetNumber.PadLeft(2, '0'));
                if (anonymizedNumber.Length > 1)
                    anonymizedNumber = anonymizedNumber.Substring(anonymizedNumber.Length - 1);
            }
            else
            {
                anonymizedNumber = _numericAnonymizer.Anonymize(components.StreetNumber);
            }
            
            result = SafeReplace(result, components.StreetNumber, anonymizedNumber);
        }
        
        // 3. City
        if (!string.IsNullOrEmpty(components.City) && !_preserveCity)
        {
            string anonymizedCity = _textAnonymizer.Anonymize(components.City);
            result = SafeReplace(result, components.City, anonymizedCity);
        }
        
        // 4. Country
        if (!string.IsNullOrEmpty(components.Country) && !_preserveCountry)
        {
            string anonymizedCountry = _textAnonymizer.Anonymize(components.Country);
            result = SafeReplace(result, components.Country, anonymizedCountry);
        }
        
        // Store mapping for later deanonymization
        _originalToAnonymized[address] = result;
        _anonymizedToOriginal[result] = address;
        
        return result;
    }
    
    public override string Deanonymize(string anonymizedAddress)
    {
        if (string.IsNullOrEmpty(anonymizedAddress))
            return anonymizedAddress;
            
        // Check for cached result
        if (_anonymizedToOriginal.TryGetValue(anonymizedAddress, out string originalAddress))
            return originalAddress;
            
        // Parse the anonymized address
        AddressComponents components = ParseAddress(anonymizedAddress);
        
        // Build a working copy
        string result = anonymizedAddress;
        
        // Process each identified component
        
        // 1. Street name
        if (!string.IsNullOrEmpty(components.StreetName))
        {
            string deanonymizedStreetName = _textAnonymizer.Deanonymize(components.StreetName);
            result = SafeReplace(result, components.StreetName, deanonymizedStreetName);
        }
        
        // 2. Street number
        if (!string.IsNullOrEmpty(components.StreetNumber) && !_preserveStreetNumber)
        {
            string deanonymizedNumber;
            
            // Handle minimum length requirement for FF3
            if (components.StreetNumber.Length < 2)
            {
                deanonymizedNumber = _numericAnonymizer.Deanonymize(components.StreetNumber.PadLeft(2, '0'));
                if (deanonymizedNumber.Length > 1)
                    deanonymizedNumber = deanonymizedNumber.Substring(deanonymizedNumber.Length - 1);
            }
            else
            {
                deanonymizedNumber = _numericAnonymizer.Deanonymize(components.StreetNumber);
            }
            
            result = SafeReplace(result, components.StreetNumber, deanonymizedNumber);
        }
        
        // 3. City
        if (!string.IsNullOrEmpty(components.City) && !_preserveCity)
        {
            string deanonymizedCity = _textAnonymizer.Deanonymize(components.City);
            result = SafeReplace(result, components.City, deanonymizedCity);
        }
        
        // 4. Country
        if (!string.IsNullOrEmpty(components.Country) && !_preserveCountry)
        {
            string deanonymizedCountry = _textAnonymizer.Deanonymize(components.Country);
            result = SafeReplace(result, components.Country, deanonymizedCountry);
        }
        
        return result;
    }
    
    private AddressComponents ParseAddress(string address)
    {
        var components = new AddressComponents();
        
        // 1. Extract postal code with regex
        var postalCodeMatch = POSTAL_CODE_PATTERN.Match(address);
        if (postalCodeMatch.Success)
        {
            components.PostalCode = postalCodeMatch.Value;
        }
        
        // 2. Extract street numbers
        var streetNumberMatches = STREET_NUMBER_PATTERN.Matches(address);
        if (streetNumberMatches.Count > 0)
        {
            foreach (Match match in streetNumberMatches)
            {
                string value = match.Groups[1].Success ? match.Groups[1].Value 
                             : match.Groups[2].Success ? match.Groups[2].Value : null;
                
                if (!string.IsNullOrEmpty(value))
                {
                    components.StreetNumber = value;
                    break;
                }
            }
        }
        
        // 3. Look for street prefixes
        string foundPrefix = null;
        int prefixPos = -1;
        
        foreach (var prefix in STREET_PREFIXES)
        {
            int pos = FindWholeWord(address, prefix);
            if (pos >= 0 && (prefixPos < 0 || pos < prefixPos))
            {
                foundPrefix = prefix;
                prefixPos = pos;
            }
        }
        
        if (foundPrefix != null)
        {
            components.StreetPrefix = foundPrefix;
        }
        
        // 4. Look for known countries
        foreach (var country in COUNTRY_NAMES)
        {
            if (FindWholeWord(address, country) >= 0)
            {
                components.Country = country;
                break;
            }
        }
        
        // 5. Extract street name - one of the most challenging parts
        if (!string.IsNullOrEmpty(components.StreetPrefix))
        {
            // If we found a street prefix, find what comes after it
            int startPos = address.IndexOf(components.StreetPrefix) + components.StreetPrefix.Length;
            int endPos = address.Length;
            
            // Find the first comma, number, or known suffix after the prefix
            int commaPos = address.IndexOf(',', startPos);
            if (commaPos > 0) endPos = Math.Min(endPos, commaPos);
            
            if (!string.IsNullOrEmpty(components.StreetNumber))
            {
                int numPos = address.IndexOf(components.StreetNumber, startPos);
                if (numPos > 0) endPos = Math.Min(endPos, numPos);
            }
            
            if (startPos < endPos)
            {
                components.StreetName = address.Substring(startPos, endPos - startPos).Trim();
            }
        }
        
        // 6. Try to extract city - typically found between commas
        var parts = address.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 1)
        {
            // Check parts that aren't at beginning or end
            for (int i = 1; i < parts.Length - 1; i++)
            {
                string part = parts[i].Trim();
                
                // Skip parts containing postal codes or containing very short texts
                if (components.PostalCode != null && part.Contains(components.PostalCode))
                    continue;
                
                if (part.Length < 3) // Too short to be a city name
                    continue;
                
                // Look for city indicators like "mun."
                if (part.Contains("mun.") || part.StartsWith("mun"))
                {
                    part = part.Replace("mun.", "").Replace("mun", "").Trim();
                    components.City = part;
                    break;
                }
                
                // Check if the part contains just a word (likely a city name)
                // without numbers or other special indicators
                if (!ContainsDigit(part) && !part.Contains("str.") && !part.Contains("bd."))
                {
                    components.City = part;
                    break;
                }
            }
            
            // If still no city found and there are enough parts, 
            // consider the second-to-last part to be the city
            if (string.IsNullOrEmpty(components.City) && parts.Length >= 3)
            {
                string candidateCity = parts[parts.Length - 2].Trim();
                
                // Simple validation - not too short, no postal code
                if (candidateCity.Length >= 3 && 
                    (components.PostalCode == null || !candidateCity.Contains(components.PostalCode)))
                {
                    components.City = candidateCity;
                }
            }
        }
        
        return components;
    }
    
    // Helper methods
    
    private string SafeReplace(string source, string oldValue, string newValue)
    {
        if (string.IsNullOrEmpty(oldValue) || !source.Contains(oldValue))
            return source;
            
        // Find positions where the old value appears as a word or phrase
        List<int> positions = new List<int>();
        int pos = 0;
        
        while ((pos = source.IndexOf(oldValue, pos, StringComparison.OrdinalIgnoreCase)) != -1)
        {
            bool isMatch = true;
            
            // Check if it's a whole word (or at least not part of another word)
            if (pos > 0 && char.IsLetterOrDigit(source[pos - 1]))
                isMatch = false;
                
            if (pos + oldValue.Length < source.Length && 
                char.IsLetterOrDigit(source[pos + oldValue.Length]))
                isMatch = false;
                
            if (isMatch)
                positions.Add(pos);
                
            pos += oldValue.Length;
        }
        
        // Replace from end to beginning to avoid position shifts
        if (positions.Count > 0)
        {
            StringBuilder result = new StringBuilder(source);
            
            foreach (int position in positions.OrderByDescending(p => p))
            {
                result.Remove(position, oldValue.Length);
                result.Insert(position, newValue);
            }
            
            return result.ToString();
        }
        
        return source;
    }
    
    private int FindWholeWord(string text, string word)
    {
        int index = 0;
        while (index < text.Length)
        {
            index = text.IndexOf(word, index, StringComparison.OrdinalIgnoreCase);
            if (index == -1)
                return -1;
                
            // Check if it's a whole word
            bool isWordStart = (index == 0 || !char.IsLetterOrDigit(text[index - 1]));
            bool isWordEnd = (index + word.Length == text.Length || 
                             !char.IsLetterOrDigit(text[index + word.Length]));
                             
            if (isWordStart && isWordEnd)
                return index;
                
            index += word.Length;
        }
        
        return -1;
    }
    
    private bool ContainsDigit(string text)
    {
        foreach (char c in text)
        {
            if (char.IsDigit(c))
                return true;
        }
        return false;
    }
    
    private class AddressComponents
    {
        public string StreetName { get; set; }
        public string StreetNumber { get; set; }
        public string StreetPrefix { get; set; }
        public string StreetSuffix { get; set; }
        public string City { get; set; }
        public string PostalCode { get; set; }
        public string Country { get; set; }
    }
}