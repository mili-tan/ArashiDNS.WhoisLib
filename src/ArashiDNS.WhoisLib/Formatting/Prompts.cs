namespace ArashiDNS.WhoisLib.Formatting;

public static class Prompts
{
    public const string SystemPrompt = @"You are a WHOIS data parser assistant. Your task is to parse raw WHOIS response data and output structured JSON.

Rules:
1. Merge identical contact information (Registrant/Admin/Tech/Billing) and add a 'roles' array field
2. Detect if WHOIS privacy protection is being used
3. Identify Registry (NIC) and Registrar information with their official websites
4. Simplify output by removing redundant fields
5. Return empty strings for missing fields, never null
6. Dates should be in ISO 8601 format (yyyy-MM-dd)
7. Status values should be lowercase with no URL prefixes
8. Name servers should be lowercase";

    public const string JsonFormatPrompt = @"Parse the following WHOIS data into the specified JSON format.

Output JSON schema:
{
  ""domain"": ""string"",
  ""registry"": {
    ""name"": ""string"",
    ""website"": ""string"",
    ""whoisServer"": ""string""
  },
  ""registrar"": {
    ""name"": ""string"",
    ""ianaId"": ""string"",
    ""website"": ""string"",
    ""whoisServer"": ""string""
  },
  ""privacy"": {
    ""isPrivate"": boolean,
    ""provider"": ""string""
  },
  ""contacts"": [
    {
      ""name"": ""string"",
      ""organization"": ""string"",
      ""email"": ""string"",
      ""phone"": ""string"",
      ""street"": ""string"",
      ""city"": ""string"",
      ""state"": ""string"",
      ""postalCode"": ""string"",
      ""country"": ""string"",
      ""roles"": [""registrant"", ""admin"", ""tech"", ""billing""]
    }
  ],
  ""dates"": {
    ""created"": ""yyyy-MM-dd"",
    ""updated"": ""yyyy-MM-dd"",
    ""expires"": ""yyyy-MM-dd""
  },
  ""nameServers"": [""string""],
  ""status"": [""string""]
}

WHOIS Raw Data:
{0}

Output JSON only, no explanations.";

    public const string EntityFormatPrompt = @"Parse the following WHOIS data into C# entity class instantiation code.

Output format example:
var whoisResult = new WhoisResponse
{
    Domain = ""example.com"",
    Registry = new RegistryInfo
    {
        Name = ""VeriSign, Inc."",
        Website = ""https://www.verisign.com""
    },
    // ... other properties
};

WHOIS Raw Data:
{0}

Output C# code only, no explanations.";

    public static string FormatJsonPrompt(string rawWhois)
    {
        return string.Format(JsonFormatPrompt, rawWhois);
    }

    public static string FormatEntityPrompt(string rawWhois)
    {
        return string.Format(EntityFormatPrompt, rawWhois);
    }
}
