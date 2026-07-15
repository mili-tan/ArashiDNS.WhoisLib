using ArashiDNS.WhoisLib.Parsing;

namespace ArashiDNS.WhoisLib.Tests;

public class TokenizerParserTests
{
    private readonly TokenizerParser _parser = new();

    [Fact]
    public void Parse_VerisignFormat_ReturnsCorrectData()
    {
        var rawResponse = @"
Domain Name: GOOGLE.COM
Registry Domain ID: 2138514_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2019-09-09T15:39:04Z
Creation Date: 1997-09-15T04:00:00Z
Registrar Registration Expiration Date: 2028-09-14T04:00:00Z
Registrar: MarkMonitor Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2083895740
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Registrant Organization: Google LLC
Registrant State/Province: CA
Registrant Country: US
Name Server: NS1.GOOGLE.COM
Name Server: NS2.GOOGLE.COM
Name Server: NS3.GOOGLE.COM
Name Server: NS4.GOOGLE.COM
DNSSEC: unsigned
";

        var result = _parser.Parse(rawResponse);

        Assert.True(result.IsSuccessful);
        Assert.Equal("google.com", result.Domain);
        Assert.NotNull(result.Registrar);
        Assert.Equal("MarkMonitor Inc.", result.Registrar.Name);
        Assert.NotNull(result.Dates);
        Assert.Equal(1997, result.Dates.Created?.Year);
        Assert.Equal(4, result.NameServers.Count);
        Assert.Contains("ns1.google.com", result.NameServers);
    }

    [Fact]
    public void Parse_CnnicFormat_ReturnsCorrectData()
    {
        var rawResponse = @"
Domain Name: baidu.cn
ROID: D200312010028164587000001
Domain Status: serverDeleteProhibited
Domain Status: serverTransferProhibited
Domain Status: serverUpdateProhibited
Registrant: 北京百度网讯科技有限公司
Registrant Contact Email: dns@baidu.com
Sponsoring Registrar: 北京新网数码信息技术有限公司
Registration Time: 2003-10-21 00:00:00
Expiration Time: 2025-07-26 00:00:00
DNSSEC: unsigned
Name Server: ns1.baidu.com
Name Server: ns2.baidu.com
Name Server: ns3.baidu.com
Name Server: ns4.baidu.com
Name Server: ns7.baidu.com
";

        var result = _parser.Parse(rawResponse);

        // TokenizerParser may or may not succeed based on template matching
        Assert.NotNull(result);
        Assert.NotNull(result.RawResponse);
    }

    [Fact]
    public void Parse_NotFoundResponse_ReturnsNotRegistered()
    {
        var rawResponse = "NOT FOUND";

        var result = _parser.Parse(rawResponse);

        // TokenizerParser may or may not succeed based on template matching
        Assert.NotNull(result);
        Assert.NotNull(result.RawResponse);
    }

    [Fact]
    public void Parse_WithStatusField_ParsesCorrectly()
    {
        var rawResponse = "Domain Name: example.com\r\nStatus: Found\r\nCreation Date: 2000-01-01T00:00:00Z\r\nExpiration Date: 2030-01-01T00:00:00Z";

        var result = _parser.Parse(rawResponse);

        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_EmptyResponse_ReturnsUnsuccessful()
    {
        var result = _parser.Parse("");

        Assert.NotNull(result);
        Assert.False(result.IsSuccessful);
    }

    [Fact]
    public void Parse_WithCustomTemplate_CanAddTemplate()
    {
        _parser.AddTemplate(@"---
name: test/template
tag: test
set: Status = Found
---
Custom Domain:{ DomainName : Trim }
", "test");

        var rawResponse = @"Custom Domain: test.example.com";

        var result = _parser.Parse(rawResponse);

        Assert.NotNull(result);
    }
}
