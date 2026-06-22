using System.Text.Json.Serialization;

namespace ArashiDNS.WhoisLib.Contracts.Models;

#region Enums

public enum WhoisQueryType
{
    Domain,
    Ipv4,
    Ipv6,
    Asn
}

#endregion

#region Core Models

public class WhoisResponse
{
    public string Query { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string RawResponse { get; set; } = string.Empty;
    public WhoisQueryType QueryType { get; set; }

    public RegistryInfo? Registry { get; set; }
    public RegistrarInfo? Registrar { get; set; }
    public PrivacyInfo? Privacy { get; set; }

    public ContactCollection Contacts { get; set; } = new();
    public DomainDates? Dates { get; set; }
    public List<string> NameServers { get; set; } = new();
    public List<string> Statuses { get; set; } = new();
    public DnssecInfo? Dnssec { get; set; }

    public string WhoisServer { get; set; } = string.Empty;
    public string? Port43 { get; set; }
    public string? RawWhoisResponse { get; set; }
    public List<string> ReferralChain { get; set; } = new();
    public bool IsSuccessful { get; set; }
    public string? ErrorMessage { get; set; }
}

public class FormattedResult
{
    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

    [JsonPropertyName("registry")]
    public RegistryInfo? Registry { get; set; }

    [JsonPropertyName("registrar")]
    public RegistrarInfo? Registrar { get; set; }

    [JsonPropertyName("privacy")]
    public PrivacyInfo? Privacy { get; set; }

    [JsonPropertyName("contacts")]
    public List<ContactInfo> Contacts { get; set; } = new();

    [JsonPropertyName("dates")]
    public DomainDates? Dates { get; set; }

    [JsonPropertyName("nameServers")]
    public List<string> NameServers { get; set; } = new();

    [JsonPropertyName("status")]
    public List<string> Statuses { get; set; } = new();

    [JsonPropertyName("dnssec")]
    public DnssecInfo? Dnssec { get; set; }

    [JsonIgnore]
    public string? RawJson { get; set; }
}

#endregion

#region Registry & Registrar

public class RegistryInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("website")]
    public string Website { get; set; } = string.Empty;

    [JsonPropertyName("whoisServer")]
    public string WhoisServer { get; set; } = string.Empty;

    [JsonIgnore]
    public string IanaId { get; set; } = string.Empty;

    [JsonIgnore]
    public string Tld { get; set; } = string.Empty;
}

public class RegistrarInfo
{
    [JsonPropertyName("ianaId")]
    public string IanaId { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("website")]
    public string Website { get; set; } = string.Empty;

    [JsonPropertyName("whoisServer")]
    public string WhoisServer { get; set; } = string.Empty;

    [JsonIgnore]
    public string RdapUrl { get; set; } = string.Empty;

    [JsonIgnore]
    public string AbuseContactEmail { get; set; } = string.Empty;

    [JsonIgnore]
    public string AbuseContactPhone { get; set; } = string.Empty;
}

public class RegistrarEntry
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string RdapBaseUrl { get; set; } = string.Empty;
}

#endregion

#region Contacts

public class ContactInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("organization")]
    public string Organization { get; set; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    [JsonPropertyName("phone")]
    public string Phone { get; set; } = string.Empty;

    [JsonPropertyName("street")]
    public string Street { get; set; } = string.Empty;

    [JsonPropertyName("city")]
    public string City { get; set; } = string.Empty;

    [JsonPropertyName("state")]
    public string State { get; set; } = string.Empty;

    [JsonPropertyName("postalCode")]
    public string PostalCode { get; set; } = string.Empty;

    [JsonPropertyName("country")]
    public string Country { get; set; } = string.Empty;

    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = new();

    [JsonIgnore]
    public bool IsPrivacyProtected { get; set; }
}

public class ContactCollection
{
    public ContactInfo? Registrant { get; set; }
    public ContactInfo? Admin { get; set; }
    public ContactInfo? Tech { get; set; }
    public ContactInfo? Billing { get; set; }

    public List<ContactInfo> GetMergedContacts()
    {
        var contacts = new List<ContactInfo>();
        var processed = new HashSet<int>();

        var allContacts = new[] { Registrant, Admin, Tech, Billing }
            .Where(c => c != null)
            .Cast<ContactInfo>()
            .ToList();

        foreach (var contact in allContacts)
        {
            var hash = GetContactHash(contact);
            if (processed.Contains(hash))
            {
                var existing = contacts.FirstOrDefault(c => GetContactHash(c) == hash);
                if (existing != null)
                {
                    if (!existing.Roles.Contains(GetRole(contact)))
                        existing.Roles.Add(GetRole(contact));
                }
            }
            else
            {
                processed.Add(hash);
                contact.Roles = new List<string> { GetRole(contact) };
                contacts.Add(contact);
            }
        }

        return contacts;
    }

    private string GetRole(ContactInfo contact)
    {
        if (contact == Registrant) return "registrant";
        if (contact == Admin) return "admin";
        if (contact == Tech) return "tech";
        if (contact == Billing) return "billing";
        return "unknown";
    }

    private int GetContactHash(ContactInfo contact)
    {
        var hash = new HashCode();
        hash.Add(contact.Name);
        hash.Add(contact.Organization);
        hash.Add(contact.Email);
        hash.Add(contact.Phone);
        hash.Add(contact.Street);
        hash.Add(contact.City);
        hash.Add(contact.State);
        hash.Add(contact.PostalCode);
        hash.Add(contact.Country);
        return hash.ToHashCode();
    }
}

#endregion

#region Privacy

public class PrivacyInfo
{
    [JsonPropertyName("isPrivate")]
    public bool IsPrivate { get; set; }

    [JsonPropertyName("provider")]
    public string? Provider { get; set; }

    [JsonIgnore]
    public List<string> Indicators { get; set; } = new();
}

#endregion

#region Dates

public class DomainDates
{
    [JsonPropertyName("created")]
    public DateTime? Created { get; set; }

    [JsonPropertyName("updated")]
    public DateTime? Updated { get; set; }

    [JsonPropertyName("expires")]
    public DateTime? Expires { get; set; }
}

#endregion

#region IP/ASN Allocations

public class IpAllocation
{
    public string Prefix { get; set; } = string.Empty;
    public int PrefixLength { get; set; }
    public string Designation { get; set; } = string.Empty;
    public string WhoisServer { get; set; } = string.Empty;
    public string RdapUrl { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
}

public class AsAllocation
{
    public long RangeStart { get; set; }
    public long RangeEnd { get; set; }
    public string Description { get; set; } = string.Empty;
    public string WhoisServer { get; set; } = string.Empty;
    public string RdapUrl { get; set; } = string.Empty;
}

#endregion

#region DNSSEC

public class DnssecInfo
{
    [JsonPropertyName("signed")]
    public bool Signed { get; set; }

    [JsonPropertyName("delegationSigned")]
    public bool DelegationSigned { get; set; }

    [JsonPropertyName("maxSigLife")]
    public int? MaxSigLife { get; set; }

    [JsonPropertyName("dsData")]
    public List<DsRecord> DsRecords { get; set; } = new();

    [JsonPropertyName("keyData")]
    public List<DnssecKey> KeyData { get; set; } = new();
}

public class DsRecord
{
    [JsonPropertyName("keyTag")]
    public int KeyTag { get; set; }

    [JsonPropertyName("algorithm")]
    public int Algorithm { get; set; }

    [JsonPropertyName("digestType")]
    public int DigestType { get; set; }

    [JsonPropertyName("digest")]
    public string Digest { get; set; } = string.Empty;
}

public class DnssecKey
{
    [JsonPropertyName("flags")]
    public int Flags { get; set; }

    [JsonPropertyName("protocol")]
    public int Protocol { get; set; }

    [JsonPropertyName("algorithm")]
    public int Algorithm { get; set; }

    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; } = string.Empty;
}

#endregion
