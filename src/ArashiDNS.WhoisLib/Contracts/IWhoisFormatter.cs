using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Contracts;

public interface IWhoisFormatter
{
    Task<FormattedResult> FormatAsync(WhoisResponse response);
}
