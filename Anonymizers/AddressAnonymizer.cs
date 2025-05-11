using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using FPE.Interfaces;

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
    
    // Child anonymizers for specialized parts
    private StringAnonymizer _streetNameAnonymizer;
    private StringAnonymizer _cityAnonymizer;
    private StringAnonymizer _countryAnonymizer;
    
    // Constants for address part detection
    private static readonly string[] STREET_PREFIXES = { "bd.", "str.", "strada", "avenue", "ave.", "blvd." };
    private static readonly string[] STREET_SUFFIXES = { "street", "st.", "road", "rd.", "boulevard", "blvd", "lane", "ln." };
    private static readonly string[] COUNTRIES = { "Moldova", "Romania", "USA", "UK", "Ukraine", "Russia" };
    
    // Regex patterns for common address components
    private static readonly Regex POSTAL_CODE_PATTERN = new Regex(@"\b([A-Z]{1,2}[-\s]?\d{1,5}|\d{5,6}|MD-\d{4})\b");
    private static readonly Regex STREET_NUMBER_PATTERN = new Regex(@"\b(\d+[A-Za-z]?)\b|nr\.?(\d+)");
    
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
        
        // Initialize child anonymizers
        _streetNameAnonymizer = new StringAnonymizer(cipher);
        _streetNameAnonymizer.SetPreserveCase(true);
        _streetNameAnonymizer.SetPreserveSpaces(true);
        _streetNameAnonymizer.SetPreservePunctuation(true);
        
        _cityAnonymizer = new StringAnonymizer(cipher);
        _cityAnonymizer.SetPreserveCase(true);
        
        _countryAnonymizer = new StringAnonymizer(cipher);
        _countryAnonymizer.SetPreserveCase(true);
    }
    
    public void SetPreservePostalCode(bool preserve)
    {
        _preservePostalCode = preserve;
    }
    
    public void SetPreserveCountry(bool preserve)
    {
        _preserveCountry = preserve;
    }
    
    public void SetPreserveCity(bool preserve)
    {
        _preserveCity = preserve;
    }
    
    public void SetPreserveStreetNumber(bool preserve)
    {
        _preserveStreetNumber = preserve;
    }
    
    public void SetPreserveStreetPrefix(bool preserve)
    {
        _preserveStreetPrefix = preserve;
    }
    
    public void SetPreserveStreetSuffix(bool preserve)
    {
        _preserveStreetSuffix = preserve;
    }
    
    public override string Anonymize(string address)
    {
        if (string.IsNullOrEmpty(address))
            return address;
            
        // Save original address for mapping
        if (_originalToAnonymized.TryGetValue(address, out string existingAnonymized))
        {
            return existingAnonymized;
        }
            
        // Track identified components for anonymization/preservation
        AddressComponents components = ParseAddress(address);
        
        // Create a working copy of the input
        string result = address;
        
        // Anonymize street name
        if (!string.IsNullOrEmpty(components.StreetName))
        {
            string streetAnonymized = _streetNameAnonymizer.Anonymize(components.StreetName);
            result = ReplaceComponent(result, components.StreetName, streetAnonymized);
        }
        
        // Handle street number
        if (!string.IsNullOrEmpty(components.StreetNumber) && !_preserveStreetNumber)
        {
            // Ensure street number meets minimum length for FPE
            string numberToEncrypt = components.StreetNumber;
            if (numberToEncrypt.Length < 2)
            {
                numberToEncrypt = numberToEncrypt.PadRight(2, '0');
            }
            
            string numberAnonymized = _streetNameAnonymizer.Anonymize(numberToEncrypt);
            
            // If original had only one digit, trim result
            if (components.StreetNumber.Length == 1)
            {
                numberAnonymized = numberAnonymized[0].ToString();
            }
            
            result = ReplaceComponent(result, components.StreetNumber, numberAnonymized);
        }
        
        // Handle city
        if (!string.IsNullOrEmpty(components.City) && !_preserveCity)
        {
            string cityAnonymized = _cityAnonymizer.Anonymize(components.City);
            result = ReplaceComponent(result, components.City, cityAnonymized);
        }
        
        // Handle country
        if (!string.IsNullOrEmpty(components.Country) && !_preserveCountry)
        {
            string countryAnonymized = _countryAnonymizer.Anonymize(components.Country);
            result = ReplaceComponent(result, components.Country, countryAnonymized);
        }
        
        // Store mappings for future deanonymization
        _originalToAnonymized[address] = result;
        _anonymizedToOriginal[result] = address;
        
        return result;
    }
    
    public override string Deanonymize(string anonymizedAddress)
    {
        // Check if we have an exact mapping first
        if (_anonymizedToOriginal.TryGetValue(anonymizedAddress, out string original))
        {
            return original;
        }
        
        // Otherwise attempt component-based deanonymization
        if (string.IsNullOrEmpty(anonymizedAddress))
            return anonymizedAddress;
            
        // Parse the anonymized address
        AddressComponents components = ParseAddress(anonymizedAddress);
        
        // Create a working copy of the input
        string result = anonymizedAddress;
        
        // Deanonymize street name if present
        if (!string.IsNullOrEmpty(components.StreetName))
        {
            string streetDeanonymized = _streetNameAnonymizer.Deanonymize(components.StreetName);
            result = ReplaceComponent(result, components.StreetName, streetDeanonymized);
        }
        
        // Handle street number
        if (!string.IsNullOrEmpty(components.StreetNumber) && !_preserveStreetNumber)
        {
            // Ensure street number meets minimum length for FPE
            string numberToDecrypt = components.StreetNumber;
            bool wasPadded = false;
            
            if (numberToDecrypt.Length < 2)
            {
                numberToDecrypt = numberToDecrypt.PadRight(2, '0');
                wasPadded = true;
            }
            
            string numberDeanonymized = _streetNameAnonymizer.Deanonymize(numberToDecrypt);
            
            // If original had only one digit, trim result
            if (wasPadded)
            {
                numberDeanonymized = numberDeanonymized[0].ToString();
            }
            
            result = ReplaceComponent(result, components.StreetNumber, numberDeanonymized);
        }
        
        // Handle city
        if (!string.IsNullOrEmpty(components.City) && !_preserveCity)
        {
            string cityDeanonymized = _cityAnonymizer.Deanonymize(components.City);
            result = ReplaceComponent(result, components.City, cityDeanonymized);
        }
        
        // Handle country
        if (!string.IsNullOrEmpty(components.Country) && !_preserveCountry)
        {
            string countryDeanonymized = _countryAnonymizer.Deanonymize(components.Country);
            result = ReplaceComponent(result, components.Country, countryDeanonymized);
        }
        
        return result;
    }
    
    private AddressComponents ParseAddress(string address)
    {
        var components = new AddressComponents();
        
        // Detect postal code
        var postalCodeMatch = POSTAL_CODE_PATTERN.Match(address);
        if (postalCodeMatch.Success)
        {
            components.PostalCode = postalCodeMatch.Value;
        }
        
        // Detect street number - look for all matches
        var streetNumberMatches = STREET_NUMBER_PATTERN.Matches(address);
        if (streetNumberMatches.Count > 0)
        {
            // Use the first match as the street number
            foreach (Match match in streetNumberMatches)
            {
                string value = match.Groups[1].Success 
                    ? match.Groups[1].Value 
                    : match.Groups[2].Value;
                
                if (!string.IsNullOrEmpty(value))
                {
                    components.StreetNumber = value;
                    break;
                }
            }
        }
        
        // Detect street prefix and suffix
        foreach (var prefix in STREET_PREFIXES)
        {
            if (ContainsWholeWord(address, prefix))
            {
                components.StreetPrefix = prefix;
                break;
            }
        }
        
        foreach (var suffix in STREET_SUFFIXES)
        {
            if (ContainsWholeWord(address, suffix))
            {
                components.StreetSuffix = suffix;
                break;
            }
        }
        
        // Extract street name using improved logic
        if (components.StreetPrefix != null || components.StreetSuffix != null)
        {
            components.StreetName = ExtractStreetName(address, components);
        }
        
        // Detect country
        foreach (var country in COUNTRIES)
        {
            if (ContainsWholeWord(address, country))
            {
                components.Country = country;
                break;
            }
        }
        
        // Detect city - look for common patterns
        var parts = address.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 1)
        {
            // Try to find city part - typically before postal code or country
            for (int i = 0; i < parts.Length; i++)
            {
                string part = parts[i].Trim();
                
                // Skip parts that are definitely not the city
                if (part.Contains(components.PostalCode) || 
                    (components.Country != null && part.Contains(components.Country)) ||
                    (components.StreetName != null && part.Contains(components.StreetName)))
                {
                    continue;
                }
                
                // Common city indicators
                if (part.Contains("mun.") || 
                    part.StartsWith("mun ") || 
                    (i > 0 && i < parts.Length - 1)) // Middle parts are often cities
                {
                    // Remove common prefixes
                    string cityCandidate = part
                        .Replace("mun.", "")
                        .Replace("mun", "")
                        .Trim();
                    
                    // Skip if it's too short
                    if (cityCandidate.Length > 2)
                    {
                        components.City = cityCandidate;
                        break;
                    }
                }
            }
        }
        
        return components;
    }
    
    private string ExtractStreetName(string address, AddressComponents components)
    {
        int startIndex = 0;
        int endIndex = address.Length;
        
        // Find start position based on prefix
        if (components.StreetPrefix != null)
        {
            int prefixPos = FindWholeWordPosition(address, components.StreetPrefix);
            if (prefixPos >= 0)
            {
                startIndex = prefixPos + components.StreetPrefix.Length;
            }
        }
        
        // Find end position
        if (components.StreetSuffix != null)
        {
            int suffixPos = FindWholeWordPosition(address, components.StreetSuffix);
            if (suffixPos > startIndex)
            {
                endIndex = suffixPos;
            }
        }
        else if (components.StreetNumber != null)
        {
            // Look for street number after the street name
            int numPos = address.IndexOf(components.StreetNumber, startIndex);
            if (numPos > startIndex)
            {
                endIndex = numPos;
            }
        }
        else
        {
            // Look for comma or other delimiter
            int commaPos = address.IndexOf(',', startIndex);
            if (commaPos > startIndex)
            {
                endIndex = commaPos;
            }
        }
        
        if (endIndex > startIndex)
        {
            string extracted = address.Substring(startIndex, endIndex - startIndex).Trim();
            
            // Clean up any trailing characters
            extracted = Regex.Replace(extracted, @"[,.]+$", "").Trim();
            
            return extracted;
        }
        
        return null;
    }
    
    private string ReplaceComponent(string source, string oldValue, string newValue)
    {
        if (string.IsNullOrEmpty(oldValue) || !source.Contains(oldValue))
            return source;
            
        // Find positions where the old value appears as a whole word
        List<int> positions = new List<int>();
        int pos = 0;
        
        while ((pos = source.IndexOf(oldValue, pos)) != -1)
        {
            // Check if whole word
            bool isWholeWord = true;
            if (pos > 0 && char.IsLetterOrDigit(source[pos - 1]))
                isWholeWord = false;
                
            if (pos + oldValue.Length < source.Length && 
                char.IsLetterOrDigit(source[pos + oldValue.Length]))
                isWholeWord = false;
                
            if (isWholeWord)
                positions.Add(pos);
                
            pos += oldValue.Length;
        }
        
        // Replace from end to beginning to maintain positions
        StringBuilder result = new StringBuilder(source);
        for (int i = positions.Count - 1; i >= 0; i--)
        {
            result.Remove(positions[i], oldValue.Length);
            result.Insert(positions[i], newValue);
        }
        
        return result.ToString();
    }
    
    private bool ContainsWholeWord(string source, string word)
    {
        return FindWholeWordPosition(source, word) >= 0;
    }
    
    private int FindWholeWordPosition(string source, string word)
    {
        int pos = 0;
        while ((pos = source.IndexOf(word, pos, StringComparison.OrdinalIgnoreCase)) != -1)
        {
            // Check if whole word
            bool isWholeWord = true;
            if (pos > 0 && char.IsLetterOrDigit(source[pos - 1]))
                isWholeWord = false;
                
            if (pos + word.Length < source.Length && 
                char.IsLetterOrDigit(source[pos + word.Length]))
                isWholeWord = false;
                
            if (isWholeWord)
                return pos;
                
            pos += word.Length;
        }
        
        return -1;
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