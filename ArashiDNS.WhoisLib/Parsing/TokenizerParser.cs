using System.Reflection;
using ArashiDNS.WhoisLib.Contracts.Models;
using Tokens;
using Tokens.Transformers;

namespace ArashiDNS.WhoisLib.Parsing;

/// <summary>
/// Tokenizer-based WHOIS parser (inspired by flipbit/whois)
/// Uses template files to match and extract WHOIS response fields
/// </summary>
public class TokenizerParser
{
    private readonly TokenMatcher _matcher;
    private bool _templatesLoaded;

    public TokenizerParser()
    {
        _matcher = new TokenMatcher();

        // Register custom transformers used in flipbit's templates
        _matcher.RegisterTransformer<CleanDomainStatusTransformer>();
        _matcher.RegisterTransformer<ToHostNameTransformer>();
    }

    public WhoisResponse Parse(string rawResponse, string? server = null)
    {
        if (string.IsNullOrWhiteSpace(rawResponse))
        {
            return new WhoisResponse
            {
                RawResponse = rawResponse,
                IsSuccessful = false,
                ErrorMessage = "Empty response"
            };
        }

        EnsureTemplatesLoaded();

        var tags = !string.IsNullOrEmpty(server)
            ? new[] { server, "catch-all" }
            : new[] { "catch-all" };

        try
        {
            var result = _matcher.Match<TokenizerResult>(rawResponse, tags);
            var match = result.BestMatch;

            if (match == null)
            {
                return new WhoisResponse
                {
                    RawResponse = rawResponse,
                    IsSuccessful = false,
                    ErrorMessage = "No template matched"
                };
            }

            var value = match.Value;
            return MapToWhoisResponse(value, rawResponse, server);
        }
        catch (Exception ex)
        {
            return new WhoisResponse
            {
                RawResponse = rawResponse,
                IsSuccessful = false,
                ErrorMessage = $"Tokenizer error: {ex.Message}"
            };
        }
    }

    private WhoisResponse MapToWhoisResponse(TokenizerResult result, string rawResponse, string? server)
    {
        var response = new WhoisResponse
        {
            RawResponse = rawResponse,
            WhoisServer = server ?? string.Empty,
            IsSuccessful = true
        };

        if (!string.IsNullOrEmpty(result.DomainName))
            response.Domain = result.DomainName.ToLowerInvariant();

        response.Statuses = result.DomainStatus ?? new List<string>();

        if (result.Registered.HasValue)
        {
            response.Dates ??= new DomainDates();
            response.Dates.Created = result.Registered;
        }
        if (result.Updated.HasValue)
        {
            response.Dates ??= new DomainDates();
            response.Dates.Updated = result.Updated;
        }
        if (result.Expiration.HasValue)
        {
            response.Dates ??= new DomainDates();
            response.Dates.Expires = result.Expiration;
        }

        response.NameServers = result.NameServers ?? new List<string>();

        if (result.Registrar != null)
        {
            response.Registrar = new RegistrarInfo
            {
                Name = result.Registrar.Name ?? string.Empty,
                IanaId = result.Registrar.IanaId ?? string.Empty,
                Website = result.Registrar.Url ?? string.Empty,
                WhoisServer = result.Registrar.WhoisServer ?? string.Empty,
                AbuseContactEmail = result.Registrar.AbuseEmail ?? string.Empty,
                AbuseContactPhone = result.Registrar.AbuseTelephoneNumber ?? string.Empty
            };
        }

        response.Contacts = BuildContacts(result);

        if (!string.IsNullOrEmpty(result.Status))
            response.IsSuccessful = result.Status == "Found";

        return response;
    }

    private ContactCollection BuildContacts(TokenizerResult result)
    {
        var contacts = new ContactCollection();

        if (result.Registrant != null)
        {
            contacts.Registrant = new ContactInfo
            {
                Name = result.Registrant.Name ?? string.Empty,
                Organization = result.Registrant.Organization ?? string.Empty,
                Email = result.Registrant.Email ?? string.Empty,
                Phone = result.Registrant.TelephoneNumber ?? string.Empty,
                Street = result.Registrant.Address ?? string.Empty
            };
        }

        if (result.AdminContact != null)
        {
            contacts.Admin = new ContactInfo
            {
                Name = result.AdminContact.Name ?? string.Empty,
                Organization = result.AdminContact.Organization ?? string.Empty,
                Email = result.AdminContact.Email ?? string.Empty,
                Phone = result.AdminContact.TelephoneNumber ?? string.Empty,
                Street = result.AdminContact.Address ?? string.Empty
            };
        }

        if (result.TechnicalContact != null)
        {
            contacts.Tech = new ContactInfo
            {
                Name = result.TechnicalContact.Name ?? string.Empty,
                Organization = result.TechnicalContact.Organization ?? string.Empty,
                Email = result.TechnicalContact.Email ?? string.Empty,
                Phone = result.TechnicalContact.TelephoneNumber ?? string.Empty,
                Street = result.TechnicalContact.Address ?? string.Empty
            };
        }

        if (result.BillingContact != null)
        {
            contacts.Billing = new ContactInfo
            {
                Name = result.BillingContact.Name ?? string.Empty,
                Organization = result.BillingContact.Organization ?? string.Empty,
                Email = result.BillingContact.Email ?? string.Empty,
                Phone = result.BillingContact.TelephoneNumber ?? string.Empty,
                Street = result.BillingContact.Address ?? string.Empty
            };
        }

        return contacts;
    }

    private void EnsureTemplatesLoaded()
    {
        if (_templatesLoaded) return;

        var assembly = Assembly.GetExecutingAssembly();
        var resourceNames = assembly.GetManifestResourceNames()
            .Where(n => n.Contains("Parsing.Templates") && n.EndsWith(".txt"));

        foreach (var resourceName in resourceNames)
        {
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null) continue;

            using var reader = new StreamReader(stream);
            var content = reader.ReadToEnd();

            try
            {
                _matcher.RegisterTemplate(content);
            }
            catch
            {
                // Skip templates that fail to register
            }
        }

        _templatesLoaded = true;
    }

    public void AddTemplate(string content, string name)
    {
        _matcher.RegisterTemplate(content);
    }

    public void ClearTemplates()
    {
        _matcher.Templates.Clear();
        _templatesLoaded = false;
    }
}

public class TokenizerResult
{
    public string? Status { get; set; }
    public string? DomainName { get; set; }
    public string? RegistryDomainId { get; set; }
    public DateTime? Registered { get; set; }
    public DateTime? Updated { get; set; }
    public DateTime? Expiration { get; set; }
    public List<string>? NameServers { get; set; }
    public List<string>? DomainStatus { get; set; }
    public string? DnsSecStatus { get; set; }
    public TokenizerRegistrar? Registrar { get; set; }
    public TokenizerContact? Registrant { get; set; }
    public TokenizerContact? AdminContact { get; set; }
    public TokenizerContact? TechnicalContact { get; set; }
    public TokenizerContact? BillingContact { get; set; }
    public TokenizerTrademark? Trademark { get; set; }
}

public class TokenizerRegistrar
{
    public string? Name { get; set; }
    public string? IanaId { get; set; }
    public string? Url { get; set; }
    public string? WhoisServer { get; set; }
    public string? AbuseEmail { get; set; }
    public string? AbuseTelephoneNumber { get; set; }
}

public class TokenizerContact
{
    public string? RegistryId { get; set; }
    public string? Name { get; set; }
    public string? Organization { get; set; }
    public string? Address { get; set; }
    public string? Email { get; set; }
    public string? TelephoneNumber { get; set; }
    public string? TelephoneNumberExt { get; set; }
    public string? FaxNumber { get; set; }
    public string? FaxNumberExt { get; set; }
}

public class TokenizerTrademark
{
    public string? Name { get; set; }
    public DateTime? Date { get; set; }
    public string? Country { get; set; }
    public string? Number { get; set; }
}

/// <summary>
/// Custom transformer for cleaning domain status values
/// Removes URLs and parenthetical content, converts to lowercase
/// </summary>
public class CleanDomainStatusTransformer : ITokenTransformer
{
    public bool CanTransform(object value, string[] args, out object? transformed)
    {
        if (value == null)
        {
            transformed = string.Empty;
            return true;
        }

        var valueString = value.ToString() ?? string.Empty;
        valueString = valueString.Trim();

        // Remove parenthetical content like "(clientTransferProhibited)"
        var parenIndex = valueString.IndexOf('(');
        if (parenIndex > 0)
            valueString = valueString[..parenIndex].Trim();

        // Remove URLs
        var urlIndex = valueString.IndexOf("http", StringComparison.OrdinalIgnoreCase);
        if (urlIndex > 0)
            valueString = valueString[..urlIndex].Trim();

        transformed = valueString.ToLowerInvariant();
        return true;
    }
}

/// <summary>
/// Custom transformer for converting values to hostnames
/// Trims, lowercases, and removes trailing dots
/// </summary>
public class ToHostNameTransformer : ITokenTransformer
{
    public bool CanTransform(object value, string[] args, out object? transformed)
    {
        if (value == null)
        {
            transformed = string.Empty;
            return true;
        }

        var valueString = value.ToString() ?? string.Empty;
        transformed = valueString.Trim().ToLowerInvariant().TrimEnd('.');
        return true;
    }
}
