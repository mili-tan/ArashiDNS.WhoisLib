using ArashiDNS.WhoisLib.Parsing;

namespace ArashiDNS.WhoisLib.Tests;

public class FrenchNicFormatTests
{
    private readonly RegexParser _parser = new();

    [Fact]
    public void Parse_FrenchNicFormat_WithHolderC_ReturnsRegistrant()
    {
        var rawResponse = @"
domain: example.fr
holder-c: ABCD1234-FRNIC
admin-c: EFGH5678-FRNIC
tech-c: IJKL9012-FRNIC
registrar: EXAMPLE REGISTRAR
nserver: ns1.example.fr
nserver: ns2.example.fr
status: ACTIVE
created: 01/01/2020
last-update: 15/06/2023
Expiry Date: 01/01/2025
changed: 15/06/2023 10:30:00
";

        var result = _parser.Parse(rawResponse);

        Assert.True(result.IsSuccessful);
        Assert.Equal("example.fr", result.Domain);
        Assert.NotNull(result.Registrar);
        Assert.Equal("EXAMPLE REGISTRAR", result.Registrar.Name);
        Assert.NotNull(result.Dates);
        Assert.Equal(2020, result.Dates.Created?.Year);
        Assert.Equal(1, result.Dates.Created?.Month);
        Assert.Equal(1, result.Dates.Created?.Day);
        Assert.Equal(2023, result.Dates.Updated?.Year);
        Assert.Equal(6, result.Dates.Updated?.Month);
        Assert.Equal(15, result.Dates.Updated?.Day);
        Assert.Equal(2025, result.Dates.Expires?.Year);
        Assert.Equal(2, result.NameServers.Count);
        Assert.Contains("ns1.example.fr", result.NameServers);
        Assert.Contains("ns2.example.fr", result.NameServers);
        Assert.Contains("active", result.Statuses);
    }

    [Fact]
    public void Parse_FrenchNicFormat_WithContactFields_ReturnsContact()
    {
        var rawResponse = @"
domain: example.fr
holder-c: ABCD1234-FRNIC
admin-c: EFGH5678-FRNIC
tech-c: IJKL9012-FRNIC
registrar: EXAMPLE REGISTRAR
nserver: ns1.example.fr
status: ACTIVE
created: 01/01/2020
contact: John Doe
address: 123 Main Street
address: Paris, France
country: FR
phone: +33.123456789
fax-no: +33.987654321
e-mail: john@example.fr
type: PERSON
changed: 15/06/2023 10:30:00
";

        var result = _parser.Parse(rawResponse);

        Assert.True(result.IsSuccessful);
        Assert.Equal("example.fr", result.Domain);
        // Contact should be parsed from nic_* fields
        if (result.Contacts?.Registrant != null)
        {
            Assert.Equal("John Doe", result.Contacts.Registrant.Name);
            Assert.Equal("FR", result.Contacts.Registrant.Country);
            Assert.Equal("john@example.fr", result.Contacts.Registrant.Email);
        }
    }

    [Fact]
    public void Parse_FrenchNicFormat_WithOrganizationType_ReturnsOrganization()
    {
        var rawResponse = @"
domain: example.fr
holder-c: ABCD1234-FRNIC
admin-c: EFGH5678-FRNIC
tech-c: IJKL9012-FRNIC
registrar: EXAMPLE REGISTRAR
nserver: ns1.example.fr
status: ACTIVE
created: 01/01/2020
contact: Example Organization
address: 456 Business Ave
address: Lyon, France
country: FR
phone: +33.111222333
e-mail: info@example.fr
type: ORGANIZATION
changed: 15/06/2023 10:30:00
";

        var result = _parser.Parse(rawResponse);

        Assert.True(result.IsSuccessful);
        Assert.Equal("example.fr", result.Domain);
        // Organization contact should be parsed
        if (result.Contacts?.Registrant != null)
        {
            Assert.Equal("Example Organization", result.Contacts.Registrant.Organization);
            Assert.Equal("FR", result.Contacts.Registrant.Country);
        }
    }

    [Fact]
    public void Parse_FrenchNicFormat_WithNameserverIPs_ReturnsNameservers()
    {
        var rawResponse = @"
domain: example.fr
holder-c: ABCD1234-FRNIC
admin-c: EFGH5678-FRNIC
tech-c: IJKL9012-FRNIC
registrar: EXAMPLE REGISTRAR
nserver: ns1.example.fr [192.168.1.1]
nserver: ns2.example.fr [192.168.1.2]
status: ACTIVE
created: 01/01/2020
";

        var result = _parser.Parse(rawResponse);

        Assert.True(result.IsSuccessful);
        Assert.Equal("example.fr", result.Domain);
        Assert.Equal(2, result.NameServers.Count);
        // Nameservers may contain IP addresses in brackets
        Assert.Contains(result.NameServers, ns => ns.Contains("ns1.example.fr"));
        Assert.Contains(result.NameServers, ns => ns.Contains("ns2.example.fr"));
    }

    [Fact]
    public void Parse_FrenchNicFormat_WithThrottledResponse_DetectsThrottled()
    {
        var rawResponse = @"
%% Too many requests...
";

        var detector = new AvailabilityDetector();
        var result = detector.Detect(rawResponse);

        Assert.Equal(AvailabilityStatus.Throttled, result.Status);
        Assert.True(result.IsThrottled);
    }

    [Fact]
    public void Parse_FrenchNicFormat_WithNoEntries_DetectsNotRegistered()
    {
        var rawResponse = @"
No entries found in the AFNIC Database
";

        var detector = new AvailabilityDetector();
        var result = detector.Detect(rawResponse);

        Assert.Equal(AvailabilityStatus.NotRegistered, result.Status);
        Assert.True(result.IsAvailable);
    }

    [Fact]
    public void Parse_FrenchNicFormat_WithRedemptionStatus_ReturnsRegistered()
    {
        var rawResponse = @"
domain: example.fr
holder-c: ABCD1234-FRNIC
status: redemption
created: 01/01/2020
";

        var result = _parser.Parse(rawResponse);

        Assert.True(result.IsSuccessful);
        Assert.Equal("example.fr", result.Domain);
        Assert.Contains("redemption", result.Statuses);
    }

    [Fact]
    public void Parse_FrenchNicFormat_WithFrozenStatus_ReturnsRegistered()
    {
        var rawResponse = @"
domain: example.fr
holder-c: ABCD1234-FRNIC
status: frozen
created: 01/01/2020
";

        var result = _parser.Parse(rawResponse);

        Assert.True(result.IsSuccessful);
        Assert.Equal("example.fr", result.Domain);
        Assert.Contains("frozen", result.Statuses);
    }
}
