using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data;
using ArashiDNS.WhoisLib.Detection;
using ArashiDNS.WhoisLib.Parsing;

namespace ArashiDNS.WhoisLib.Formatting;

/// <summary>
/// Multi-layer formatter that combines multiple parsing strategies:
/// Layer 1: TokenizerParser (template-based, inspired by flipbit/whois)
/// Layer 2: RegexWhoisParserWrapper (234 server-specific parsers from ArashiDNS.RegexWhoisParser)
/// Layer 3: TraditionalParser (field mapping, original implementation)
/// Layer 4: SectionParser (section-based, for .kg, .cn etc.)
/// Layer 5: LlmFormatter (LLM-based, final fallback)
/// </summary>
public class MultiLayerFormatter : IWhoisFormatter
{
    private readonly MultiLayerParser _parser;
    private readonly TraditionalFormatter _traditionalFormatter;
    private readonly LlmFormatter? _llmFormatter;
    private readonly PrivacyDetector _privacyDetector;
    private readonly RegistryIdentifier _registryIdentifier;
    private readonly AvailabilityDetector _availabilityDetector;

    public string LastUsedLayer { get; private set; } = string.Empty;

    public MultiLayerFormatter(
        RegistrarListProvider registrarProvider,
        LlmFormatterOptions? llmOptions = null)
    {
        _parser = new MultiLayerParser();
        _traditionalFormatter = new TraditionalFormatter(registrarProvider);
        _privacyDetector = new PrivacyDetector();
        _registryIdentifier = new RegistryIdentifier(registrarProvider);
        _availabilityDetector = new AvailabilityDetector();

        if (llmOptions != null && !string.IsNullOrEmpty(llmOptions.ApiKey))
        {
            _llmFormatter = new LlmFormatter(llmOptions);
        }
    }

    public MultiLayerFormatter(
        TraditionalFormatter traditionalFormatter,
        LlmFormatter? llmFormatter,
        RegistrarListProvider registrarProvider)
    {
        _parser = new MultiLayerParser();
        _traditionalFormatter = traditionalFormatter;
        _llmFormatter = llmFormatter;
        _privacyDetector = new PrivacyDetector();
        _registryIdentifier = new RegistryIdentifier(registrarProvider);
        _availabilityDetector = new AvailabilityDetector();
    }

    public async Task<FormattedResult> FormatAsync(WhoisResponse response)
    {
        if (response.QueryType is WhoisQueryType.Ipv4 or WhoisQueryType.Ipv6)
            return await FormatIpResponseAsync(response);

        if (response.QueryType == WhoisQueryType.Asn)
            return await FormatIpResponseAsync(response);

        return await FormatDomainResponseAsync(response);
    }

    private async Task<FormattedResult> FormatDomainResponseAsync(WhoisResponse response)
    {
        if (!string.IsNullOrEmpty(response.RawResponse))
        {
            var availability = _availabilityDetector.Detect(response.RawResponse);
            if (availability.IsAvailable)
            {
                return new FormattedResult
                {
                    Domain = response.Query,
                    Statuses = ["available"],
                    Privacy = new PrivacyInfo { IsPrivate = false }
                };
            }
        }

        var result = await TryMultiLayerParseAsync(response);
        if (result != null && HasUsefulData(result))
        {
            return PostProcess(result, response);
        }

        result = await TryTraditionalParseAsync(response);
        if (result != null && HasUsefulData(result))
        {
            return PostProcess(result, response);
        }

        result = await TryLlmParseAsync(response);
        if (result != null)
        {
            return PostProcess(result, response);
        }

        return CreateFallbackResult(response);
    }

    private async Task<FormattedResult?> TryMultiLayerParseAsync(WhoisResponse response)
    {
        try
        {
            if (string.IsNullOrEmpty(response.RawResponse))
                return null;

            var parsed = _parser.Parse(response.RawResponse, response.WhoisServer);

            MergeResponses(response, parsed);

            var result = BuildFormattedResult(response);

            var fieldCount = CountFilledFields(result);
            if (fieldCount > 0)
            {
                LastUsedLayer = "Tokenizer";
            }

            return result;
        }
        catch
        {
            return null;
        }
    }

    private async Task<FormattedResult?> TryTraditionalParseAsync(WhoisResponse response)
    {
        try
        {
            var result = await _traditionalFormatter.FormatAsync(response);
            if (HasUsefulData(result))
            {
                LastUsedLayer = "Regex";
                return result;
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    private async Task<FormattedResult?> TryLlmParseAsync(WhoisResponse response)
    {
        if (_llmFormatter == null)
            return null;

        try
        {
            var result = await _llmFormatter.FormatAsync(response);
            LastUsedLayer = "LLM";
            return result;
        }
        catch
        {
            return null;
        }
    }

    private void MergeResponses(WhoisResponse target, WhoisResponse source)
    {
        if (!string.IsNullOrEmpty(source.Domain) && string.IsNullOrEmpty(target.Domain))
            target.Domain = source.Domain;

        if (source.Dates != null)
        {
            target.Dates ??= new DomainDates();
            if (source.Dates.Created != null && target.Dates.Created == null)
                target.Dates.Created = source.Dates.Created;
            if (source.Dates.Updated != null && target.Dates.Updated == null)
                target.Dates.Updated = source.Dates.Updated;
            if (source.Dates.Expires != null && target.Dates.Expires == null)
                target.Dates.Expires = source.Dates.Expires;
        }

        if (source.NameServers.Count > 0 && target.NameServers.Count == 0)
            target.NameServers = source.NameServers;

        if (source.Statuses.Count > 0 && target.Statuses.Count == 0)
            target.Statuses = source.Statuses;

        if (source.Registrar != null && (target.Registrar == null || string.IsNullOrEmpty(target.Registrar.Name)))
            target.Registrar = source.Registrar;

        if (source.Contacts != null)
        {
            target.Contacts ??= new ContactCollection();
            if (source.Contacts.Registrant != null && target.Contacts.Registrant == null)
                target.Contacts.Registrant = source.Contacts.Registrant;
            if (source.Contacts.Admin != null && target.Contacts.Admin == null)
                target.Contacts.Admin = source.Contacts.Admin;
            if (source.Contacts.Tech != null && target.Contacts.Tech == null)
                target.Contacts.Tech = source.Contacts.Tech;
            if (source.Contacts.Billing != null && target.Contacts.Billing == null)
                target.Contacts.Billing = source.Contacts.Billing;
        }

        if (source.Dnssec != null && target.Dnssec == null)
            target.Dnssec = source.Dnssec;
    }

    private FormattedResult BuildFormattedResult(WhoisResponse response)
    {
        return new FormattedResult
        {
            Domain = response.Domain ?? response.Query,
            Registry = response.Registry,
            Registrar = response.Registrar,
            Contacts = response.Contacts?.GetMergedContacts() ?? new List<ContactInfo>(),
            Dates = response.Dates,
            NameServers = response.NameServers ?? new List<string>(),
            Statuses = response.Statuses ?? new List<string>(),
            Dnssec = response.Dnssec
        };
    }

    private static bool HasUsefulData(FormattedResult result)
    {
        if (!string.IsNullOrEmpty(result.Domain) && result.Domain != "unknown")
            return true;

        if (result.NameServers.Count > 0)
            return true;

        if (result.Statuses.Count > 0 && !result.Statuses.Contains("available"))
            return true;

        if (result.Dates?.Created != null || result.Dates?.Expires != null)
            return true;

        if (result.Registrar != null && !string.IsNullOrEmpty(result.Registrar.Name))
            return true;

        if (result.Contacts?.Count > 0)
        {
            var first = result.Contacts[0];
            if (!string.IsNullOrEmpty(first.Name) || !string.IsNullOrEmpty(first.Organization) || !string.IsNullOrEmpty(first.Email))
                return true;
        }

        return false;
    }

    private FormattedResult PostProcess(FormattedResult result, WhoisResponse response)
    {
        result.Privacy = _privacyDetector.Detect(response);

        response.Domain = result.Domain;
        response.Registrar = result.Registrar;
        response.Dates = result.Dates;
        response.NameServers = result.NameServers;
        response.Statuses = result.Statuses;

        response.Privacy = result.Privacy;
        response.Registry = result.Registry;

        return result;
    }

    private FormattedResult CreateFallbackResult(WhoisResponse response)
    {
        response.Domain ??= response.Query;

        response.Privacy = _privacyDetector.Detect(response);

        return new FormattedResult
        {
            Domain = response.Domain,
            Registry = response.Registry,
            Registrar = response.Registrar,
            Privacy = response.Privacy,
            Contacts = response.Contacts?.GetMergedContacts() ?? new List<ContactInfo>(),
            Dates = response.Dates,
            NameServers = response.NameServers ?? new List<string>(),
            Statuses = response.Statuses ?? new List<string>(),
            Dnssec = response.Dnssec
        };
    }

    private async Task<FormattedResult> FormatIpResponseAsync(WhoisResponse response)
    {
        if (string.IsNullOrEmpty(response.Domain) && !string.IsNullOrEmpty(response.RawResponse))
        {
            var parsed = _parser.Parse(response.RawResponse, response.WhoisServer);
            if (!string.IsNullOrEmpty(parsed.Domain))
                response.Domain = parsed.Domain;
        }

        if (string.IsNullOrEmpty(response.Domain))
            response.Domain = response.Query;

        if (response.Registry == null || string.IsNullOrEmpty(response.Registry.Name))
        {
            if (!string.IsNullOrEmpty(response.RawResponse))
            {
                var parsed = _parser.Parse(response.RawResponse, response.WhoisServer);
                if (parsed.Registry != null && !string.IsNullOrEmpty(parsed.Registry.Name))
                    response.Registry = parsed.Registry;
            }

            response.Registry ??= new RegistryInfo { WhoisServer = response.WhoisServer };
        }

        response.Privacy = _privacyDetector.Detect(response);

        return new FormattedResult
        {
            Domain = response.Domain,
            Registry = response.Registry,
            Privacy = response.Privacy,
            Contacts = response.Contacts?.GetMergedContacts() ?? [],
            NameServers = response.NameServers ?? [],
            Statuses = response.Statuses ?? []
        };
    }

    public void AddTemplate(string content, string name)
    {
        _parser.AddTokenizerTemplate(content, name);
    }

    public void ClearTemplates()
    {
        _parser.ClearTokenizerTemplates();
    }

    private static int CountFilledFields(FormattedResult result)
    {
        var count = 0;

        if (!string.IsNullOrEmpty(result.Domain)) count++;
        if (result.Registrar != null && !string.IsNullOrEmpty(result.Registrar.Name)) count++;
        if (result.Dates?.Created != null) count++;
        if (result.Dates?.Updated != null) count++;
        if (result.Dates?.Expires != null) count++;
        if (result.NameServers?.Count > 0) count += result.NameServers.Count;
        if (result.Statuses?.Count > 0) count += result.Statuses.Count;

        if (result.Contacts?.Count > 0)
        {
            foreach (var contact in result.Contacts)
            {
                if (!string.IsNullOrEmpty(contact.Name)) count++;
                if (!string.IsNullOrEmpty(contact.Organization)) count++;
                if (!string.IsNullOrEmpty(contact.Email)) count++;
                if (!string.IsNullOrEmpty(contact.Phone)) count++;
                if (!string.IsNullOrEmpty(contact.Country)) count++;
            }
        }

        return count;
    }
}
