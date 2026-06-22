using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Contracts;

public interface IWhoisClient
{
    Task<WhoisResponse> QueryAsync(string query);
    Task<WhoisResponse> QueryAsync(string query, string server);
    Task<WhoisResponse> QueryAsync(string query, WhoisQueryType queryType);
}
