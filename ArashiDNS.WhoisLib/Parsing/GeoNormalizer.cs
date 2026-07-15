using System.Text.RegularExpressions;

namespace ArashiDNS.WhoisLib.Parsing;

/// <summary>
/// Normalizes geographic information (country/region) from WHOIS/RDAP responses
/// </summary>
public partial class GeoNormalizer
{
    private static readonly Dictionary<string, string> CountryCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["AF"] = "Afghanistan", ["AL"] = "Albania", ["DZ"] = "Algeria", ["AD"] = "Andorra",
        ["AO"] = "Angola", ["AG"] = "Antigua and Barbuda", ["AR"] = "Argentina", ["AM"] = "Armenia",
        ["AU"] = "Australia", ["AT"] = "Austria", ["AZ"] = "Azerbaijan", ["BS"] = "Bahamas",
        ["BH"] = "Bahrain", ["BD"] = "Bangladesh", ["BB"] = "Barbados", ["BY"] = "Belarus",
        ["BE"] = "Belgium", ["BZ"] = "Belize", ["BJ"] = "Benin", ["BT"] = "Bhutan",
        ["BO"] = "Bolivia", ["BA"] = "Bosnia and Herzegovina", ["BW"] = "Botswana", ["BR"] = "Brazil",
        ["BN"] = "Brunei", ["BG"] = "Bulgaria", ["BF"] = "Burkina Faso", ["BI"] = "Burundi",
        ["KH"] = "Cambodia", ["CM"] = "Cameroon", ["CA"] = "Canada", ["CV"] = "Cape Verde",
        ["CF"] = "Central African Republic", ["TD"] = "Chad", ["CL"] = "Chile", ["CN"] = "China",
        ["CO"] = "Colombia", ["KM"] = "Comoros", ["CG"] = "Congo", ["CD"] = "Congo (DRC)",
        ["CR"] = "Costa Rica", ["CI"] = "Cote d'Ivoire", ["HR"] = "Croatia", ["CU"] = "Cuba",
        ["CY"] = "Cyprus", ["CZ"] = "Czech Republic", ["DK"] = "Denmark", ["DJ"] = "Djibouti",
        ["DM"] = "Dominica", ["DO"] = "Dominican Republic", ["EC"] = "Ecuador", ["EG"] = "Egypt",
        ["SV"] = "El Salvador", ["GQ"] = "Equatorial Guinea", ["ER"] = "Eritrea", ["EE"] = "Estonia",
        ["ET"] = "Ethiopia", ["FJ"] = "Fiji", ["FI"] = "Finland", ["FR"] = "France",
        ["GA"] = "Gabon", ["GM"] = "Gambia", ["GE"] = "Georgia", ["DE"] = "Germany",
        ["GH"] = "Ghana", ["GR"] = "Greece", ["GD"] = "Grenada", ["GT"] = "Guatemala",
        ["GN"] = "Guinea", ["GW"] = "Guinea-Bissau", ["GY"] = "Guyana", ["HT"] = "Haiti",
        ["HN"] = "Honduras", ["HK"] = "Hong Kong", ["HU"] = "Hungary", ["IS"] = "Iceland",
        ["IN"] = "India", ["ID"] = "Indonesia", ["IR"] = "Iran", ["IQ"] = "Iraq",
        ["IE"] = "Ireland", ["IL"] = "Israel", ["IT"] = "Italy", ["JM"] = "Jamaica",
        ["JP"] = "Japan", ["JO"] = "Jordan", ["KZ"] = "Kazakhstan", ["KE"] = "Kenya",
        ["KI"] = "Kiribati", ["KP"] = "North Korea", ["KR"] = "South Korea", ["KW"] = "Kuwait",
        ["KG"] = "Kyrgyzstan", ["LA"] = "Laos", ["LV"] = "Latvia", ["LB"] = "Lebanon",
        ["LS"] = "Lesotho", ["LR"] = "Liberia", ["LY"] = "Libya", ["LI"] = "Liechtenstein",
        ["LT"] = "Lithuania", ["LU"] = "Luxembourg", ["MO"] = "Macao", ["MK"] = "North Macedonia",
        ["MG"] = "Madagascar", ["MW"] = "Malawi", ["MY"] = "Malaysia", ["MV"] = "Maldives",
        ["ML"] = "Mali", ["MT"] = "Malta", ["MH"] = "Marshall Islands", ["MR"] = "Mauritania",
        ["MU"] = "Mauritius", ["MX"] = "Mexico", ["FM"] = "Micronesia", ["MD"] = "Moldova",
        ["MC"] = "Monaco", ["MN"] = "Mongolia", ["ME"] = "Montenegro", ["MA"] = "Morocco",
        ["MZ"] = "Mozambique", ["MM"] = "Myanmar", ["NA"] = "Namibia", ["NR"] = "Nauru",
        ["NP"] = "Nepal", ["NL"] = "Netherlands", ["NZ"] = "New Zealand", ["NI"] = "Nicaragua",
        ["NE"] = "Niger", ["NG"] = "Nigeria", ["NO"] = "Norway", ["OM"] = "Oman",
        ["PK"] = "Pakistan", ["PW"] = "Palau", ["PA"] = "Panama", ["PG"] = "Papua New Guinea",
        ["PY"] = "Paraguay", ["PE"] = "Peru", ["PH"] = "Philippines", ["PL"] = "Poland",
        ["PT"] = "Portugal", ["QA"] = "Qatar", ["RO"] = "Romania", ["RU"] = "Russia",
        ["RW"] = "Rwanda", ["KN"] = "Saint Kitts and Nevis", ["LC"] = "Saint Lucia",
        ["VC"] = "Saint Vincent and the Grenadines", ["WS"] = "Samoa", ["SM"] = "San Marino",
        ["ST"] = "Sao Tome and Principe", ["SA"] = "Saudi Arabia", ["SN"] = "Senegal",
        ["RS"] = "Serbia", ["SC"] = "Seychelles", ["SL"] = "Sierra Leone", ["SG"] = "Singapore",
        ["SK"] = "Slovakia", ["SI"] = "Slovenia", ["SB"] = "Solomon Islands", ["SO"] = "Somalia",
        ["ZA"] = "South Africa", ["SS"] = "South Sudan", ["ES"] = "Spain", ["LK"] = "Sri Lanka",
        ["SD"] = "Sudan", ["SR"] = "Suriname", ["SE"] = "Sweden", ["CH"] = "Switzerland",
        ["SY"] = "Syria", ["TW"] = "Taiwan", ["TJ"] = "Tajikistan", ["TZ"] = "Tanzania",
        ["TH"] = "Thailand", ["TL"] = "Timor-Leste", ["TG"] = "Togo", ["TO"] = "Tonga",
        ["TT"] = "Trinidad and Tobago", ["TN"] = "Tunisia", ["TR"] = "Turkey", ["TM"] = "Turkmenistan",
        ["TV"] = "Tuvalu", ["UG"] = "Uganda", ["UA"] = "Ukraine", ["AE"] = "United Arab Emirates",
        ["GB"] = "United Kingdom", ["UK"] = "United Kingdom", ["US"] = "United States",
        ["UY"] = "Uruguay", ["UZ"] = "Uzbekistan", ["VU"] = "Vanuatu", ["VE"] = "Venezuela",
        ["VN"] = "Vietnam", ["YE"] = "Yemen", ["ZM"] = "Zambia", ["ZW"] = "Zimbabwe",
        ["XK"] = "Kosovo", ["PS"] = "Palestine", ["EU"] = "European Union",
        ["AP"] = "Asia/Pacific Region", ["ASIA"] = "Asia"
    };

    private static readonly Dictionary<string, string> CountryAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["USA"] = "US", ["U.S.A."] = "US", ["U.S."] = "US", ["UNITED STATES"] = "US",
        ["UNITED STATES OF AMERICA"] = "US",
        ["UK"] = "GB", ["UNITED KINGDOM"] = "GB", ["GREAT BRITAIN"] = "GB", ["ENGLAND"] = "GB",
        ["CHINA"] = "CN", ["PRC"] = "CN", ["PEOPLES REPUBLIC OF CHINA"] = "CN",
        ["JAPAN"] = "JP", ["JAPAN"] = "JP",
        ["KOREA"] = "KR", ["SOUTH KOREA"] = "KR", ["REPUBLIC OF KOREA"] = "KR",
        ["NORTH KOREA"] = "KP",
        ["GERMANY"] = "DE", ["DEUTSCHLAND"] = "DE",
        ["FRANCE"] = "FR", ["FRENCH REPUBLIC"] = "FR",
        ["ITALY"] = "IT", ["ITALIA"] = "IT",
        ["SPAIN"] = "ES", ["ESPANA"] = "ES",
        ["BRAZIL"] = "BR", ["BRASIL"] = "BR",
        ["RUSSIA"] = "RU", ["RUSSIAN FEDERATION"] = "RU",
        ["INDIA"] = "IN",
        ["AUSTRALIA"] = "AU",
        ["CANADA"] = "CA",
        ["MEXICO"] = "MX", ["MEXICO"] = "MX",
        ["ARGENTINA"] = "AR",
        ["COLOMBIA"] = "CO",
        ["CHILE"] = "CL",
        ["PERU"] = "PE",
        ["VENEZUELA"] = "VE",
        ["TURKEY"] = "TR", ["TURKIYE"] = "TR",
        ["SAUDI ARABIA"] = "SA",
        ["UNITED ARAB EMIRATES"] = "AE", ["UAE"] = "AE",
        ["SINGAPORE"] = "SG",
        ["MALAYSIA"] = "MY",
        ["THAILAND"] = "TH",
        ["VIETNAM"] = "VN", ["VIET NAM"] = "VN",
        ["INDONESIA"] = "ID",
        ["PHILIPPINES"] = "PH",
        ["TAIWAN"] = "TW", ["TAIPEI"] = "TW",
        ["HONG KONG"] = "HK",
        ["MACAO"] = "MO", ["MACAU"] = "MO",
        ["NEW ZEALAND"] = "NZ", ["NZ"] = "NZ",
        ["SWEDEN"] = "SE",
        ["NORWAY"] = "NO",
        ["DENMARK"] = "DK",
        ["FINLAND"] = "FI",
        ["NETHERLANDS"] = "NL", ["HOLLAND"] = "NL",
        ["BELGIUM"] = "BE",
        ["SWITZERLAND"] = "CH", ["SUISSE"] = "CH", ["SCHWEIZ"] = "CH",
        ["AUSTRIA"] = "AT", ["OSTERREICH"] = "AT",
        ["POLAND"] = "PL", ["POLSKA"] = "PL",
        ["CZECH REPUBLIC"] = "CZ", ["CZECHIA"] = "CZ",
        ["HUNGARY"] = "HU",
        ["ROMANIA"] = "RO",
        ["BULGARIA"] = "BG",
        ["GREECE"] = "GR",
        ["PORTUGAL"] = "PT",
        ["IRELAND"] = "IE", ["EIRE"] = "IE",
        ["ISRAEL"] = "IL",
        ["EGYPT"] = "EG",
        ["SOUTH AFRICA"] = "ZA",
        ["NIGERIA"] = "NG",
        ["KENYA"] = "KE",
        ["ETHIOPIA"] = "ET",
        ["GHANA"] = "GH",
        ["TANZANIA"] = "TZ",
        ["MOROCCO"] = "MA",
        ["ALGERIA"] = "DZ",
        ["TUNISIA"] = "TN",
        ["IRAQ"] = "IQ",
        ["IRAN"] = "IR",
        ["PAKISTAN"] = "PK",
        ["BANGLADESH"] = "BD",
        ["MYANMAR"] = "MM", ["BURMA"] = "MM",
        ["SRI LANKA"] = "LK",
        ["NEPAL"] = "NP",
        ["CAMBODIA"] = "KH",
        ["LAOS"] = "LA",
        ["MONGOLIA"] = "MN",
        ["AFGHANISTAN"] = "AF",
        ["UZBEKISTAN"] = "UZ",
        ["KAZAKHSTAN"] = "KZ",
        ["GEORGIA"] = "GE",
        ["ARMENIA"] = "AM",
        ["AZERBAIJAN"] = "AZ",
        ["UKRAINE"] = "UA",
        ["BELARUS"] = "BY",
        ["LITHUANIA"] = "LT",
        ["LATVIA"] = "LV",
        ["ESTONIA"] = "EE",
        ["CROATIA"] = "HR",
        ["SERBIA"] = "RS",
        ["SLOVENIA"] = "SI",
        ["SLOVAKIA"] = "SK",
        ["BOSNIA AND HERZEGOVINA"] = "BA", ["BOSNIA"] = "BA",
        ["NORTH MACEDONIA"] = "MK", ["MACEDONIA"] = "MK",
        ["MONTENEGRO"] = "ME",
        ["ALBANIA"] = "AL",
        ["MOLDOVA"] = "MD",
        ["CYPRUS"] = "CY",
        ["MALTA"] = "MT",
        ["LUXEMBOURG"] = "LU",
        ["LIECHTENSTEIN"] = "LI",
        ["MONACO"] = "MC",
        ["ANDORRA"] = "AD",
        ["SAN MARINO"] = "SM",
        ["VATICAN"] = "VA", ["HOLY SEE"] = "VA",
        ["ICELAND"] = "IS",
        ["JAMAICA"] = "JM",
        ["TRINIDAD AND TOBAGO"] = "TT", ["TRINIDAD"] = "TT",
        ["CUBA"] = "CU",
        ["DOMINICAN REPUBLIC"] = "DO",
        ["HAITI"] = "HT",
        ["COSTA RICA"] = "CR",
        ["PANAMA"] = "PA",
        ["GUATEMALA"] = "GT",
        ["HONDURAS"] = "HN",
        ["EL SALVADOR"] = "SV",
        ["NICARAGUA"] = "NI",
        ["ECUADOR"] = "EC",
        ["BOLIVIA"] = "BO",
        ["PARAGUAY"] = "PY",
        ["URUGUAY"] = "UY",
        ["GUYANA"] = "GY",
        ["SURINAME"] = "SR",
        ["BERMUDA"] = "BM",
        ["BAHAMAS"] = "BS",
        ["BARBADOS"] = "BB",
        ["BELIZE"] = "BZ",
        ["PAPUA NEW GUINEA"] = "PG", ["PNG"] = "PG",
        ["FIJI"] = "FJ",
        ["TONGA"] = "TO",
        ["SAMOA"] = "WS",
        ["VANUATU"] = "VU",
        ["SOLOMON ISLANDS"] = "SB",
        ["MICRONESIA"] = "FM",
        ["PALAU"] = "PW",
        ["MARSHALL ISLANDS"] = "MH",
        ["KIRIBATI"] = "KI",
        ["TUVALU"] = "TV",
        ["NAURU"] = "NR",
        ["CABO VERDE"] = "CV", ["CAPE VERDE"] = "CV",
        ["COMOROS"] = "KM",
        ["MAURITIUS"] = "MU",
        ["SEYCHELLES"] = "SC",
        ["DJIBOUTI"] = "DJ",
        ["ERITREA"] = "ER",
        ["SOMALIA"] = "SO",
        ["BURUNDI"] = "BI",
        ["RWANDA"] = "RW",
        ["MALAWI"] = "MW",
        ["ZAMBIA"] = "ZM",
        ["ZIMBABWE"] = "ZW",
        ["BOTSWANA"] = "BW",
        ["NAMIBIA"] = "NA",
        ["LESOTHO"] = "LS",
        ["ESWATINI"] = "SZ", ["SWAZILAND"] = "SZ",
        ["MADAGASCAR"] = "MG",
        ["MAURITANIA"] = "MR",
        ["MALI"] = "ML",
        ["NIGER"] = "NE",
        ["CHAD"] = "TD",
        ["CENTRAL AFRICAN REPUBLIC"] = "CF",
        ["CAMEROON"] = "CM",
        ["GABON"] = "GA",
        ["EQUATORIAL GUINEA"] = "GQ",
        ["CONGO"] = "CG",
        ["CONGO (DRC)"] = "CD", ["DEMOCRATIC REPUBLIC OF THE CONGO"] = "CD",
        ["LIBYA"] = "LY",
        ["SUDAN"] = "SD",
        ["SOUTH SUDAN"] = "SS",
        ["GUINEA"] = "GN",
        ["GUINEA-BISSAU"] = "GW",
        ["SIERRA LEONE"] = "SL",
        ["LIBERIA"] = "LR",
        ["COTE D'IVOIRE"] = "CI", ["IVORY COAST"] = "CI",
        ["BURKINA FASO"] = "BF",
        ["TOGO"] = "TG",
        ["BENIN"] = "BJ",
        ["GAMBIA"] = "GM",
        ["SENEGAL"] = "SN",
        ["ANGOLA"] = "AO",
        ["MOZAMBIQUE"] = "MZ",
        ["TIMOR-LESTE"] = "TL", ["EAST TIMOR"] = "TL",
        ["BHUTAN"] = "BT",
        ["BRUNEI"] = "BN",
        ["MALDIVES"] = "MV",
        ["LAOS"] = "LA",
        ["MYANMAR"] = "MM",
        ["NEPAL"] = "NP",
        ["SINGAPORE"] = "SG",
        ["MALAYSIA"] = "MY",
        ["THAILAND"] = "TH",
        ["VIETNAM"] = "VN",
        ["INDONESIA"] = "ID",
        ["PHILIPPINES"] = "PH",
        ["TAIWAN"] = "TW",
        ["HONG KONG"] = "HK",
        ["MACAO"] = "MO",
        ["JAPAN"] = "JP",
        ["SOUTH KOREA"] = "KR",
        ["NORTH KOREA"] = "KP",
        ["CHINA"] = "CN",
        ["INDIA"] = "IN",
        ["PAKISTAN"] = "PK",
        ["BANGLADESH"] = "BD",
        ["SRI LANKA"] = "LK",
        ["MYANMAR"] = "MM",
        ["CAMBODIA"] = "KH",
        ["LAOS"] = "LA",
        ["MONGOLIA"] = "MN",
        ["AFGHANISTAN"] = "AF",
        ["UZBEKISTAN"] = "UZ",
        ["KAZAKHSTAN"] = "KZ",
        ["TURKMENISTAN"] = "TM",
        ["TAJIKISTAN"] = "TJ",
        ["KYRGYZSTAN"] = "KG",
        ["GEORGIA"] = "GE",
        ["ARMENIA"] = "AM",
        ["AZERBAIJAN"] = "AZ",
        ["TURKEY"] = "TR",
        ["CYPRUS"] = "CY",
        ["ISRAEL"] = "IL",
        ["LEBANON"] = "LB",
        ["JORDAN"] = "JO",
        ["IRAQ"] = "IQ",
        ["IRAN"] = "IR",
        ["SAUDI ARABIA"] = "SA",
        ["YEMEN"] = "YE",
        ["OMAN"] = "OM",
        ["UNITED ARAB EMIRATES"] = "AE",
        ["QATAR"] = "QA",
        ["BAHRAIN"] = "BH",
        ["KUWAIT"] = "KW",
        ["EGYPT"] = "EG",
        ["SUDAN"] = "SD",
        ["LIBYA"] = "LY",
        ["TUNISIA"] = "TN",
        ["ALGERIA"] = "DZ",
        ["MOROCCO"] = "MA",
        ["SOUTH AFRICA"] = "ZA",
        ["NIGERIA"] = "NG",
        ["KENYA"] = "KE",
        ["ETHIOPIA"] = "ET",
        ["GHANA"] = "GH",
        ["TANZANIA"] = "TZ",
        ["UGANDA"] = "UG",
        ["MOZAMBIQUE"] = "MZ",
        ["MADAGASCAR"] = "MG",
        ["ANGOLA"] = "AO",
        ["CAMEROON"] = "CM",
        ["COTE D'IVOIRE"] = "CI",
        ["NIGER"] = "NE",
        ["BURKINA FASO"] = "BF",
        ["MALI"] = "ML",
        ["MALAWI"] = "MW",
        ["ZAMBIA"] = "ZM",
        ["SENEGAL"] = "SN",
        ["CHAD"] = "TD",
        ["SOMALIA"] = "SO",
        ["ZIMBABWE"] = "ZW",
        ["GUINEA"] = "GN",
        ["RWANDA"] = "RW",
        ["BENIN"] = "BJ",
        ["BURUNDI"] = "BI",
        ["TUNISIA"] = "TN",
        ["SOUTH SUDAN"] = "SS",
        ["TOGO"] = "TG",
        ["SIERRA LEONE"] = "SL",
        ["LIBERIA"] = "LR",
        ["CENTRAL AFRICAN REPUBLIC"] = "CF",
        ["MAURITANIA"] = "MR",
        ["ERITREA"] = "ER",
        ["GAMBIA"] = "GM",
        ["BOTSWANA"] = "BW",
        ["GABON"] = "GA",
        ["LESOTHO"] = "LS",
        ["GUINEA-BISSAU"] = "GW",
        ["EQUATORIAL GUINEA"] = "GQ",
        ["MAURITIUS"] = "MU",
        ["ESWATINI"] = "SZ",
        ["DJIBOUTI"] = "DJ",
        ["FIJI"] = "FJ",
        ["COMOROS"] = "KM",
        ["SOLOMON ISLANDS"] = "SB",
        ["CABO VERDE"] = "CV",
        ["LUXEMBOURG"] = "LU",
        ["SURINAME"] = "SR",
        ["MALTA"] = "MT",
        ["BRUNEI"] = "BN",
        ["BAHAMAS"] = "BS",
        ["BELIZE"] = "BZ",
        ["BARBADOS"] = "BB",
        ["ICELAND"] = "IS",
        ["VANUATU"] = "VU",
        ["SAMOA"] = "WS",
        ["SAO TOME AND PRINCIPE"] = "ST",
        ["SAINT LUCIA"] = "LC",
        ["SAINT VINCENT AND THE GRENADINES"] = "VC",
        ["SEYCHELLES"] = "SC",
        ["KIRIBATI"] = "KI",
        ["MICRONESIA"] = "FM",
        ["GRENADA"] = "GD",
        ["TONGA"] = "TO",
        ["SAINT KITTS AND NEVIS"] = "KN",
        ["ANTIGUA AND BARBUDA"] = "AG",
        ["TRINIDAD AND TOBAGO"] = "TT",
        ["DOMINICA"] = "DM",
        ["TUVALU"] = "TV",
        ["NAURU"] = "NR",
        ["MARSHALL ISLANDS"] = "MH",
        ["PALAU"] = "PW",
        ["ANDORRA"] = "AD",
        ["SAN MARINO"] = "SM",
        ["LIECHTENSTEIN"] = "LI",
        ["MONACO"] = "MC",
        ["VATICAN"] = "VA",
    };

    public GeoInfo Normalize(string? country, string? state = null, string? city = null, string? street = null)
    {
        var info = new GeoInfo
        {
            Country = country,
            State = state,
            City = city,
            Street = street
        };

        if (!string.IsNullOrEmpty(country))
        {
            info.CountryCode = IdentifyCountryCode(country);
            if (!string.IsNullOrEmpty(info.CountryCode) && CountryCodes.TryGetValue(info.CountryCode, out var fullName))
            {
                info.Country = fullName;
            }
        }

        return info;
    }

    public string? IdentifyCountryCode(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;

        input = input.Trim();

        if (input.Length == 2 && CountryCodes.ContainsKey(input.ToUpperInvariant()))
            return input.ToUpperInvariant();

        if (CountryAliases.TryGetValue(input, out var code))
            return code;

        var upper = input.ToUpperInvariant();
        if (CountryAliases.TryGetValue(upper, out code))
            return code;

        foreach (var kvp in CountryCodes)
        {
            if (string.Equals(kvp.Value, input, StringComparison.OrdinalIgnoreCase))
                return kvp.Key;
        }

        foreach (var kvp in CountryAliases)
        {
            if (string.Equals(kvp.Key, input, StringComparison.OrdinalIgnoreCase))
                return kvp.Value;
        }

        return null;
    }

    public string? ExtractCountryFromAddress(string? address)
    {
        if (string.IsNullOrWhiteSpace(address))
            return null;

        var parts = address.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 0)
        {
            var lastPart = parts[^1].Trim();
            var code = IdentifyCountryCode(lastPart);
            if (code != null) return code;

            foreach (var kvp in CountryCodes)
            {
                if (lastPart.Contains(kvp.Value, StringComparison.OrdinalIgnoreCase))
                    return kvp.Key;
            }
        }

        return null;
    }
}

public class GeoInfo
{
    public string? Country { get; set; }
    public string? CountryCode { get; set; }
    public string? State { get; set; }
    public string? City { get; set; }
    public string? Street { get; set; }
}
