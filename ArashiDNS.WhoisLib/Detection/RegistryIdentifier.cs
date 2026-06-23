using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data;

namespace ArashiDNS.WhoisLib.Detection;

/// <summary>
/// Registry/Registrar identifier
/// </summary>
public class RegistryIdentifier
{
    private readonly RegistrarListProvider _registrarProvider;

    public RegistryIdentifier(RegistrarListProvider registrarProvider)
    {
        _registrarProvider = registrarProvider;
    }

    public async Task<RegistryInfo?> IdentifyRegistryAsync(WhoisResponse response)
    {
        if (response.Registry != null && !string.IsNullOrEmpty(response.Registry.Name))
        {
            return response.Registry;
        }

        var tld = response.Registry?.Tld ?? ExtractTld(response.Domain);
        if (string.IsNullOrEmpty(tld))
            return null;

        return TldRegistryProvider.GetRegistryInfo(tld) ?? new RegistryInfo
        {
            Tld = tld,
            WhoisServer = response.WhoisServer
        };
    }

    public async Task<RegistrarInfo?> IdentifyRegistrarAsync(WhoisResponse response)
    {
        if (response.Registrar == null || string.IsNullOrEmpty(response.Registrar.Name))
            return null;

        var registrar = response.Registrar;

        if (!string.IsNullOrEmpty(registrar.IanaId))
        {
            var entry = await _registrarProvider.FindRegistrarByIdAsync(registrar.IanaId);
            if (entry != null)
            {
                registrar.Website = entry.RdapBaseUrl;
                return registrar;
            }
        }

        if (!string.IsNullOrEmpty(registrar.Name))
        {
            var entry = await _registrarProvider.FindRegistrarByNameAsync(registrar.Name);
            if (entry != null)
            {
                registrar.IanaId = entry.Id;
                registrar.Website = entry.RdapBaseUrl;
                return registrar;
            }
        }

        return registrar;
    }

    private static string ExtractTld(string domain)
    {
        if (string.IsNullOrEmpty(domain))
            return string.Empty;

        var parts = domain.TrimEnd('.').Split('.');
        return parts.Length > 0 ? parts[^1].ToLowerInvariant() : string.Empty;
    }
}
