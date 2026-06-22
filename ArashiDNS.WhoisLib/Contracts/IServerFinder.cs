using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Contracts;

public interface IServerFinder
{
    Task<string?> FindServerAsync(string query, WhoisQueryType queryType);
}
