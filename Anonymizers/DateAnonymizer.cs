// Anonymizers/DateAnonymizer.cs - Modified to be stateless
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
            
            // Parts that will be encrypted
            int newYear = year;
            int newMonth = month;
            int newDay = day;
            
            // Encrypt each component individually using a deterministic method
            if (!_preserveYear)
            {
                string yearStr = year.ToString("D4");
                string encryptedYear = _cipher.WithCustomAlphabet(Alphabets.Digits).Encrypt(yearStr);
                newYear = ValidateYear(encryptedYear);
            }
            
            if (!_preserveMonth)
            {
                string monthStr = month.ToString("D2");
                string encryptedMonth = _cipher.WithCustomAlphabet(Alphabets.Digits).Encrypt(monthStr);
                newMonth = ValidateMonth(encryptedMonth);
            }
            
            if (!_preserveDay)
            {
                string dayStr = day.ToString("D2");
                string encryptedDay = _cipher.WithCustomAlphabet(Alphabets.Digits).Encrypt(dayStr);
                newDay = ValidateDay(encryptedDay, newYear, newMonth);
            }
            
            DateTime newDate = new DateTime(newYear, newMonth, newDay);
            
            // Format according to output format
            return newDate.ToString(_outputFormat);
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
            
            // Now decrypt each component
            int originalYear = encryptedYear;
            int originalMonth = encryptedMonth;
            int originalDay = encryptedDay;
            
            if (!_preserveYear)
            {
                // We need to find a year that when encrypted gives us encryptedYear
                // This is computationally expensive but for dates it's manageable
                for (int testYear = 1950; testYear <= 2050; testYear++)
                {
                    string testYearStr = testYear.ToString("D4");
                    string testEncrypted = _cipher.WithCustomAlphabet(Alphabets.Digits).Encrypt(testYearStr);
                    int testEncryptedYear = ValidateYear(testEncrypted);
                    
                    if (testEncryptedYear == encryptedYear)
                    {
                        originalYear = testYear;
                        break;
                    }
                }
            }
            
            if (!_preserveMonth)
            {
                // Try each month (1-12)
                for (int testMonth = 1; testMonth <= 12; testMonth++)
                {
                    string testMonthStr = testMonth.ToString("D2");
                    string testEncrypted = _cipher.WithCustomAlphabet(Alphabets.Digits).Encrypt(testMonthStr);
                    int testEncryptedMonth = ValidateMonth(testEncrypted);
                    
                    if (testEncryptedMonth == encryptedMonth)
                    {
                        originalMonth = testMonth;
                        break;
                    }
                }
            }
            
            if (!_preserveDay)
            {
                // Get the max day for this month/year
                int maxDay = DateTime.DaysInMonth(originalYear, originalMonth);
                
                // Try each possible day
                for (int testDay = 1; testDay <= maxDay; testDay++)
                {
                    string testDayStr = testDay.ToString("D2");
                    string testEncrypted = _cipher.WithCustomAlphabet(Alphabets.Digits).Encrypt(testDayStr);
                    int testEncryptedDay = ValidateDay(testEncrypted, encryptedYear, encryptedMonth);
                    
                    if (testEncryptedDay == encryptedDay)
                    {
                        originalDay = testDay;
                        break;
                    }
                }
            }
            
            // Create the original date
            DateTime originalDate = new DateTime(originalYear, originalMonth, originalDay);
            return originalDate.ToString(_inputFormat);
        }
        catch (Exception)
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