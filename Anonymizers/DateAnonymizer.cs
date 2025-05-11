// Anonymizers/DateAnonymizer.cs
using System;
using System.Globalization;
using FPE.Interfaces;
using static FPE.Constants.Constants;

namespace FPE.Anonymizers;

public class DateAnonymizer : BaseAnonymizer
{
    private bool _preserveYear;
    private bool _preserveMonth;
    private bool _preserveDay;
    private string _inputFormat;
    private string _outputFormat;
    
    // Store original components for deanonymization
    private Dictionary<string, Dictionary<string, int>> _originalComponents = 
        new Dictionary<string, Dictionary<string, int>>();
    
    public DateAnonymizer(IFF3Cipher cipher) : base(cipher)
    {
        _preserveYear = false;
        _preserveMonth = false;
        _preserveDay = false;
        _inputFormat = "yyyy-MM-dd";
        _outputFormat = "yyyy-MM-dd";
    }
    
    public void SetPreserveYear(bool preserve)
    {
        _preserveYear = preserve;
    }
    
    public void SetPreserveMonth(bool preserve)
    {
        _preserveMonth = preserve;
    }
    
    public void SetPreserveDay(bool preserve)
    {
        _preserveDay = preserve;
    }
    
    public void SetDateFormat(string format)
    {
        _inputFormat = format;
        _outputFormat = format;
    }
    
    public void SetInputFormat(string format)
    {
        _inputFormat = format;
    }
    
    public void SetOutputFormat(string format)
    {
        _outputFormat = format;
    }
    
    public override string Anonymize(string date)
    {
        try
        {
            // Try to parse the date
            DateTime dt;
            if (!DateTime.TryParseExact(date, _inputFormat, CultureInfo.InvariantCulture, 
                DateTimeStyles.None, out dt))
            {
                return base.Anonymize(date);
            }
            
            // Extract components
            int year = dt.Year;
            int month = dt.Month;
            int day = dt.Day;
            
            // Store original components for later deanonymization
            var components = new Dictionary<string, int> {
                { "year", year },
                { "month", month },
                { "day", day }
            };
            
            // Use date string as key
            _originalComponents[date] = components;
            
            // Parts that will be encrypted
            Dictionary<string, string> partsToEncrypt = new Dictionary<string, string>();
            
            if (!_preserveYear)
            {
                partsToEncrypt["year"] = year.ToString("D4");
            }
            
            if (!_preserveMonth)
            {
                partsToEncrypt["month"] = month.ToString("D2");
            }
            
            if (!_preserveDay)
            {
                partsToEncrypt["day"] = day.ToString("D2");
            }
            
            // Encrypt the parts
            Dictionary<string, string> encryptedParts = new Dictionary<string, string>();
            
            foreach (var part in partsToEncrypt)
            {
                string encrypted = _cipher.WithCustomAlphabet(Alphabets.Digits).Encrypt(part.Value);
                encryptedParts[part.Key] = encrypted;
            }
            
            // Create new date with either original or encrypted parts
            int newYear = _preserveYear ? year : ValidateYear(encryptedParts["year"]);
            int newMonth = _preserveMonth ? month : ValidateMonth(encryptedParts["month"]);
            int newDay = _preserveDay ? day : ValidateDay(encryptedParts["day"], newYear, newMonth);
            
            DateTime newDate = new DateTime(newYear, newMonth, newDay);
            
            // Format according to output format
            string result = newDate.ToString(_outputFormat);
            
            // Store the mapping from anonymized to original
            if (!_originalComponents.ContainsKey(result))
            {
                _originalComponents[result] = components;
            }
            
            return result;
        }
        catch (Exception)
        {
            // If date parsing or manipulation fails, use the base anonymizer
            return base.Anonymize(date);
        }
    }
    
    public override string Deanonymize(string anonymizedDate)
{
    try
    {
        // Parse the anonymized date
        DateTime dt;
        if (!DateTime.TryParseExact(anonymizedDate, _outputFormat, CultureInfo.InvariantCulture,
            DateTimeStyles.None, out dt))
        {
            return base.Deanonymize(anonymizedDate);
        }
        
        // Extract components
        int encryptedYear = dt.Year;
        int encryptedMonth = dt.Month;
        int encryptedDay = dt.Day;
        
        // Create parts to decrypt
        Dictionary<string, string> partsToDecrypt = new Dictionary<string, string>();
        
        if (!_preserveYear)
        {
            partsToDecrypt["year"] = encryptedYear.ToString("D4");
        }
        
        if (!_preserveMonth)
        {
            partsToDecrypt["month"] = encryptedMonth.ToString("D2");
        }
        
        if (!_preserveDay)
        {
            partsToDecrypt["day"] = encryptedDay.ToString("D2");
        }
        
        // Decrypt the parts
        Dictionary<string, string> decryptedParts = new Dictionary<string, string>();
        
        foreach (var part in partsToDecrypt)
        {
            try
            {
                string decrypted = _cipher.WithCustomAlphabet(Alphabets.Digits).Decrypt(part.Value);
                decryptedParts[part.Key] = decrypted;
            }
            catch
            {
                // If decryption fails, use the encrypted value
                decryptedParts[part.Key] = part.Value;
            }
        }
        
        // Create original date with either anonymized or decrypted parts
        int originalYear = _preserveYear ? encryptedYear : int.Parse(decryptedParts["year"]);
        int originalMonth = _preserveMonth ? encryptedMonth : int.Parse(decryptedParts["month"]);
        int originalDay = _preserveDay ? encryptedDay : int.Parse(decryptedParts["day"]);
        
        // Validate the components
        originalYear = Math.Max(1, Math.Min(9999, originalYear));
        originalMonth = Math.Max(1, Math.Min(12, originalMonth));
        originalDay = Math.Max(1, Math.Min(DateTime.DaysInMonth(originalYear, originalMonth), originalDay));
        
        DateTime originalDate = new DateTime(originalYear, originalMonth, originalDay);
        
        return originalDate.ToString(_inputFormat);
    }
    catch
    {
        // If anything fails, use base implementation
        return base.Deanonymize(anonymizedDate);
    }
}
    
    private int ValidateYear(string encryptedYear)
    {
        // Ensure year is between 1000-9999
        string yearStr = encryptedYear.Length > 4 ? encryptedYear.Substring(0, 4) : encryptedYear.PadLeft(4, '0');
        int year = int.Parse(yearStr);
        return Math.Max(1000, Math.Min(9999, year));
    }
    
    private int ValidateMonth(string encryptedMonth)
    {
        // Ensure month is between 1-12
        int month = int.Parse(encryptedMonth) % 12;
        return month == 0 ? 12 : month; // 0 becomes 12
    }
    
    private int ValidateDay(string encryptedDay, int year, int month)
    {
        // Ensure day is valid for the month/year
        int maxDay = DateTime.DaysInMonth(year, month);
        int day = int.Parse(encryptedDay) % maxDay;
        return day == 0 ? maxDay : day; // 0 becomes maxDay
    }
}