namespace PiiExplorer.Core;

internal static class TableContext
{
    // Explicit column semantics are evidence. Never promote generic IDs or arbitrary
    // nine-digit numbers to SSNs. Recognize every column, including repeated headers.
    public static string Label(string header) => header.Trim().ToLowerInvariant()
        .Replace('_', ' ').Replace('-', ' ') switch
    {
        "name" or "full name" or "fullname" => "Full name: ",
        "dob" or "date of birth" or "birthdate" or "birth date" or "dateofbirth" => "DOB: ",
        "ssn" or "social security" or "social security number" or "socialsecuritynumber" => "SSN: ",
        "passport" or "passport number" or "passport no" => "Passport number: ",
        "driver license" or "driver's license" or "drivers license" or "driving licence" or
        "driver license number" or "drivers license number" or "driving licence number" => "Driver's license: ",
        "account number" or "account no" or "bank account" or "bank account number" => "Account number: ",
        "tax id" or "tax identification number" or "tin" => "Tax ID: ",
        _ => ""
    };
}
