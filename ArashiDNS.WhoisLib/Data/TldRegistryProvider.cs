using System.Collections.Concurrent;

namespace ArashiDNS.WhoisLib.Data;

public class TldRegistryProvider
{
    public record TldInfo(string RegistryName, string? Website = null, string? WhoisServer = null, string? RdapEndpoint = null);

    private static readonly ConcurrentDictionary<string, TldInfo> TldData = new(StringComparer.OrdinalIgnoreCase)
    {
        // Verisign
        ["com"] = new("Verisign", "https://www.verisign.com", "whois.verisign-grs.com", "https://rdap.verisign.com/com/v1/"),
        ["net"] = new("Verisign", "https://www.verisign.com", "whois.verisign-grs.com", "https://rdap.verisign.com/net/v1/"),
        
        // Generic TLDs
        ["org"] = new("Public Interest Registry (PIR)", "https://pir.org", "whois.pir.org", "https://rdap.publicinterestregistry.org/rdap/"),
        ["info"] = new("Identity Digital", "https://identity.digital", "whois.afilias.net", "https://rdap.identitydigital.services/rdap/"),
        ["biz"] = new("GoDaddy Registry", "https://www.godaddy.com", "whois.nic.biz"),
        ["name"] = new("Verisign", "https://www.verisign.com"),
        ["pro"] = new("Identity Digital", "https://identity.digital"),
        ["mobi"] = new("Identity Digital", "https://identity.digital"),
        ["asia"] = new("DotAsia Organisation", "https://www.dot.asia"),
        ["tel"] = new("Telnic", "https://www.telnic.org"),
        ["aero"] = new("SITA", "https://www.aero"),
        ["coop"] = new("DotCooperation LLC", "https://www.coop"),
        ["museum"] = new("Museum Domain Management Association", "https://www.museum"),
        ["cat"] = new("Fundacio puntCAT", "https://www.domini.cat"),
        ["jobs"] = new("Employ Media", "https://www.jobs", "jobswhois.verisign-grs.com"),
        ["travel"] = new("Identity Digital", "https://identity.digital"),
        ["post"] = new("Universal Postal Union", "https://www.post"),
        ["edu"] = new("Educause", "https://www.educause.edu", "whois.educause.edu"),
        ["gov"] = new("CISA (US gov)", "https://www.cisa.gov", "whois.dotgov.gov"),
        ["mil"] = new("DoD Network Information Center", "https://www.defense.gov", "whois.nic.mil"),
        ["int"] = new("IANA", "https://www.iana.org", "whois.iana.org"),
        
        // Google Registry
        ["dev"] = new("Google Registry (Charleston Road Registry)", "https://www.registry.google", "whois.nic.google", "https://pubapi.registry.google/rdap/"),
        ["app"] = new("Google Registry (Charleston Road Registry)", "https://www.registry.google", "whois.nic.google", "https://pubapi.registry.google/rdap/"),
        ["page"] = new("Google Registry", "https://www.registry.google", "whois.nic.google", "https://pubapi.registry.google/rdap/"),
        ["new"] = new("Google Registry", "https://www.registry.google", "whois.nic.google", "https://pubapi.registry.google/rdap/"),
        ["youtube"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["google"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["gmail"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["android"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["boo"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["cal"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["channel"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["chrome"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["dad"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["day"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["dclk"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["docs"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["drive"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["eat"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["esq"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["fly"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["foo"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["gbiz"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["gle"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["goog"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["guge"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["hangout"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["here"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["how"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["ing"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["map"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["meme"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["mov"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["nexus"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["prof"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["rsvp"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["search"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        ["soy"] = new("Google Registry", "https://www.registry.google", null, "https://pubapi.registry.google/rdap/"),
        
        // CentralNIC
        ["xyz"] = new("XYZ.com LLC", "https://www.xyz", "whois.nic.xyz", "https://rdap.centralnic.com/xyz/"),
        ["co"] = new("GoDaddy Registry (.CO Internet)", "https://www.co", "whois.nic.co", "https://rdap.centralnic.com/co/"),
        ["ai"] = new("Government of Anguilla (gov.ai)", "https://gov.ai", "whois.nic.ai", "https://rdap.identitydigital.services/rdap/"),
        ["io"] = new("Internet Computer Bureau", "https://www.nic.io", "whois.nic.io", "https://rdap.nic.io/"),
        ["design"] = new("Identity Digital", "https://www.design", "whois.nic.design"),
        ["ink"] = new("Identity Digital", "https://www.ink", "whois.nic.ink"),
        ["online"] = new("Radix", "https://www.online", "whois.nic.online"),
        ["site"] = new("Radix", "https://www.site", "whois.nic.site"),
        ["tech"] = new("Radix", "https://www.tech", "whois.nic.tech"),
        ["store"] = new("Radix", "https://www.store", "whois.nic.store"),
        ["fun"] = new("Radix", "https://www.fun", "whois.nic.fun"),
        ["press"] = new("Radix", "https://www.press", "whois.nic.press"),
        ["space"] = new("Radix", "https://www.space", "whois.nic.space"),
        ["website"] = new("Radix", "https://www.website", "whois.nic.website"),
        ["uno"] = new("Radix", "https://www.uno", "whois.nic.uno"),
        ["bond"] = new("CentralNic", "https://www.bond", "whois.nic.bond"),
        ["cfd"] = new("CentralNic", "https://www.cfd", "whois.nic.cfd"),
        ["cyou"] = new("CentralNic", "https://www.cyou", "whois.nic.cyou"),
        ["sbs"] = new("CentralNic", "https://www.sbs", "whois.nic.sbs"),
        ["icu"] = new("ShortDot", "https://www.icu", "whois.nic.icu"),
        
        // Identity Digital with WHOIS
        ["blog"] = new("Knock Knock WHOIS There (Automattic)", "https://www.blog", "whois.nic.blog"),
        ["cloud"] = new("Aruba PEC", "https://www.cloud", "whois.nic.cloud"),
        ["shop"] = new("GMO Registry", "https://www.shop", "whois.nic.shop"),
        ["ltd"] = new("Identity Digital", "https://www.ltd", "whois.nic.ltd"),
        ["group"] = new("Identity Digital", "https://www.group", "whois.nic.group"),
        ["club"] = new("Registry Services (GoDaddy)", "https://www.club", "whois.nic.club"),
        ["vip"] = new("Identity Digital", "https://www.vip", "whois.nic.vip"),
        ["top"] = new("CentralNic", "https://www.top", "whois.nic.top"),
        ["buzz"] = new("Identity Digital", "https://www.buzz", "whois.nic.buzz"),
        ["live"] = new("Identity Digital", "https://www.live", "whois.nic.live"),
        ["life"] = new("Identity Digital", "https://www.life", "whois.nic.life"),
        ["world"] = new("Identity Digital", "https://www.world", "whois.nic.world"),
        ["work"] = new("Identity Digital", "https://www.work", "whois.nic.work"),
        ["today"] = new("Identity Digital", "https://www.today", "whois.nic.today"),
        ["news"] = new("Identity Digital", "https://www.news", "whois.nic.news"),
        ["email"] = new("Identity Digital", "https://www.email", "whois.nic.email"),
        ["host"] = new("Radix", "https://www.host", "whois.nic.host"),
        ["click"] = new("UNR / Nova Registry", "https://www.click", "whois.nic.click"),
        ["help"] = new("UNR / Nova Registry", "https://www.help", "whois.nic.help"),
        ["link"] = new("UNR / Nova Registry", "https://www.link", "whois.nic.link"),
        ["guru"] = new("Identity Digital", "https://www.guru", "whois.nic.guru"),
        ["tips"] = new("Identity Digital", "https://www.tips", "whois.nic.tips"),
        ["zone"] = new("Identity Digital", "https://www.zone", "whois.nic.zone"),
        
        // Country code TLDs - Europe
        ["uk"] = new("Nominet UK", "https://www.nominet.uk", "whois.nic.uk", "https://rdap.nominet.uk/uk/"),
        ["co.uk"] = new("Nominet UK", "https://www.nominet.uk", "whois.nic.uk", "https://rdap.nominet.uk/uk/"),
        ["de"] = new("DENIC eG", "https://www.denic.de", "whois.denic.de", "https://rdap.denic.de/"),
        ["fr"] = new("Afnic", "https://www.afnic.fr", "whois.nic.fr", "https://rdap.nic.fr/"),
        ["it"] = new("IIT-CNR (Registro.it)", "https://www.nic.it", "whois.nic.it", "https://rdap.nic.it/"),
        ["nl"] = new("SIDN", "https://www.sidn.nl", "whois.sidn.nl", "https://rdap.sidn.nl/"),
        ["be"] = new("DNS Belgium", "https://www.dnsbelgium.be", "whois.dns.be", "https://rdap.dns.be/"),
        ["at"] = new("nic.at", "https://www.nic.at", "whois.nic.at", "https://rdap.nic.at/"),
        ["ch"] = new("SWITCH", "https://www.switch.ch", "whois.nic.ch", "https://rdap.nic.ch/"),
        ["es"] = new("Red.es", "https://www.red.es", "whois.nic.es", "https://rdap.nic.es/"),
        ["pt"] = new("DNS.PT", "https://www.dns.pt", "whois.dns.pt", "https://rdap.dns.pt/"),
        ["pl"] = new("NASK", "https://www.nask.pl", "whois.dns.pl"),
        ["cz"] = new("CZ.NIC", "https://www.nic.cz", "whois.nic.cz", "https://rdap.nic.cz/"),
        ["se"] = new("Internetstiftelsen (IIS)", "https://www.iis.se", "whois.iis.se", "https://rdap.iis.se/"),
        ["no"] = new("Norid", "https://www.norid.no", "whois.norid.no", "https://rdap.norid.no/"),
        ["dk"] = new("DK Hostmaster", "https://www.dk-hostmaster.dk", "whois.dk-hostmaster.dk", "https://rdap.dk-hostmaster.dk/"),
        ["fi"] = new("Traficom", "https://www.traficom.fi", "whois.fi", "https://rdap.fi/"),
        ["ie"] = new("Regist.ie (.IE)", "https://www.weare.ie", "whois.domainregistry.ie"),
        ["eu"] = new("EURid", "https://eurid.eu", "whois.eu", "https://rdap.eu/"),
        
        // Country code TLDs - Asia Pacific
        ["ru"] = new("Coordination Center for TLD RU", "https://cctld.ru", "whois.tcinet.ru", "https://rdap.tcinet.ru/"),
        ["su"] = new("Coordination Center for TLD RU", "https://cctld.ru", "whois.tcinet.ru", "https://rdap.tcinet.ru/"),
        ["cn"] = new("CNNIC", "https://www.cnnic.cn", "whois.cnnic.cn"),
        ["jp"] = new("JPRS", "https://jprs.jp", "whois.jprs.jp", "https://rdap.jprs.jp/"),
        ["kr"] = new("KISA", "https://www.kisa.or.kr", "whois.kr", "https://rdap.kr/"),
        ["tw"] = new("TWNIC", "https://www.twnic.tw", "whois.twnic.tw"),
        ["hk"] = new("HKIRC", "https://www.hkirc.hk", "whois.hkirc.hk"),
        ["sg"] = new("SGNIC", "https://www.sgnic.sg", "whois.sgnic.sg"),
        ["au"] = new("auDA", "https://www.auda.org.au", "whois.auda.org.au", "https://rdap.auda.org.au/"),
        ["nz"] = new("InternetNZ", "https://www.internetnz.nz", "whois.nzrs.net.nz", "https://rdap.nzrs.net.nz/"),
        ["ca"] = new("CIRA", "https://www.cira.ca", "whois.cira.ca"),
        ["mx"] = new("NIC México", "https://www.nic.mx", "whois.mx"),
        ["br"] = new("NIC.br / Registro.br", "https://registro.br", "whois.registro.br", "https://rdap.registro.br/"),
        ["ar"] = new("NIC Argentina", "https://www.nic.ar", "whois.nic.ar"),
        ["cl"] = new("NIC Chile", "https://www.nic.cl", "whois.nic.cl"),
        ["in"] = new("NIXI", "https://www.nixi.in", "whois.inregistry.net"),
        ["th"] = new("THNIC", "https://www.thnic.co.th"),
        ["vn"] = new("VNNIC", "https://www.vnnic.vn"),
        ["my"] = new("MYNIC", "https://www.mynic.my"),
        ["ph"] = new("dotPH", "https://www.dot.ph"),
        ["id"] = new("PANDI", "https://pandi.id"),
        
        // Country code TLDs - Middle East & Africa
        ["il"] = new("ISOC-IL", "https://www.isoc.org.il"),
        ["sa"] = new("NIC.sa", "https://www.nic.net.sa"),
        ["ae"] = new("aeDA (TDRA)", "https://www.aeda.net.ae"),
        ["qa"] = new("Qatar Domains Registry", "https://www.domains.qa"),
        ["tr"] = new("TRABIS", "https://www.trabis.gov.tr"),
        ["ua"] = new("Hostmaster Ltd", "https://www.ua"),
        ["za"] = new("ZADNA", "https://www.zadna.org.za"),
        ["ng"] = new("NIRA", "https://www.nira.org.ng"),
        ["ke"] = new("Kenic", "https://www.kenic.or.ke"),
        
        // Other ccTLDs
        ["me"] = new("doMEn (GoDaddy Registry)", "https://www.domain.me", "whois.nic.me"),
        ["cc"] = new("eNIC / Verisign", "https://www.nic.cc", "whois.nic.cc"),
        ["tv"] = new("Verisign", "https://www.nic.tv", "whois.nic.tv"),
        ["ws"] = new("Website.ws", "https://www.website.ws", "whois.website.ws"),
        ["fm"] = new("FSM Telecom", "https://www.dot.fm"),
        ["gg"] = new("Channel Islands Network (CIDR)", "https://www.gg"),
        ["ly"] = new("Libya Telecom (LTT)", "https://www.nic.ly"),
        ["is"] = new("ISNIC", "https://www.isnic.is"),
    };

    public static string? GetWhoisServer(string tld)
    {
        return TldData.TryGetValue(tld, out var info) ? info.WhoisServer : null;
    }

    public static string? GetRdapEndpoint(string tld)
    {
        return TldData.TryGetValue(tld, out var info) ? info.RdapEndpoint : null;
    }

    public static Contracts.Models.RegistryInfo? GetRegistryInfo(string tld)
    {
        if (!TldData.TryGetValue(tld, out var info))
            return null;

        return new Contracts.Models.RegistryInfo
        {
            Name = info.RegistryName,
            Website = info.Website ?? "",
            WhoisServer = info.WhoisServer ?? "",
            Tld = tld
        };
    }

    public static IReadOnlyDictionary<string, TldInfo> GetAll() => TldData;
}
