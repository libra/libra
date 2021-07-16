/**
 * See: https://github.com/samayo/country-json/blob/master/src/country-by-abbreviation.json
 * See: https://github.com/lukes/ISO-3166-Countries-with-Regional-Codes/blob/master/all/all.json
 */
const CountryCodes = [
  {
    "country": "Afghanistan",
    "abbreviation": "AF"
  },
  {
    "country": "Åland Islands",
    "abbreviation": "AX"
  },
  {
    "country": "Albania",
    "abbreviation": "AL"
  },
  {
    "country": "Algeria",
    "abbreviation": "DZ"
  },
  {
    "country": "American Samoa",
    "abbreviation": "AS"
  },
  {
    "country": "Andorra",
    "abbreviation": "AD"
  },
  {
    "country": "Angola",
    "abbreviation": "AO"
  },
  {
    "country": "Anguilla",
    "abbreviation": "AI"
  },
  {
    "country": "Antarctica",
    "abbreviation": "AQ"
  },
  {
    "country": "Antigua and Barbuda",
    "abbreviation": "AG"
  },
  {
    "country": "Argentina",
    "abbreviation": "AR"
  },
  {
    "country": "Armenia",
    "abbreviation": "AM"
  },
  {
    "country": "Aruba",
    "abbreviation": "AW"
  },
  {
    "country": "Australia",
    "abbreviation": "AU"
  },
  {
    "country": "Austria",
    "abbreviation": "AT"
  },
  {
    "country": "Azerbaijan",
    "abbreviation": "AZ"
  },
  {
    "country": "Bahamas",
    "abbreviation": "BS"
  },
  {
    "country": "Bahrain",
    "abbreviation": "BH"
  },
  {
    "country": "Bangladesh",
    "abbreviation": "BD"
  },
  {
    "country": "Barbados",
    "abbreviation": "BB"
  },
  {
    "country": "Belarus",
    "abbreviation": "BY"
  },
  {
    "country": "Belgium",
    "abbreviation": "BE"
  },
  {
    "country": "Belize",
    "abbreviation": "BZ"
  },
  {
    "country": "Benin",
    "abbreviation": "BJ"
  },
  {
    "country": "Bermuda",
    "abbreviation": "BM"
  },
  {
    "country": "Bhutan",
    "abbreviation": "BT"
  },
  {
    "country": "Bolivia",
    "abbreviation": "BO"
  },
  {
    "country": "Bonaire, Sint Eustatius and Saba",
    "abbreviation": "BQ"
  },
  {
    "country": "Bosnia and Herzegovina",
    "abbreviation": "BA"
  },
  {
    "country": "Botswana",
    "abbreviation": "BW"
  },
  {
    "country": "Bouvet Island",
    "abbreviation": "BV"
  },
  {
    "country": "Brazil",
    "abbreviation": "BR"
  },
  {
    "country": "British Indian Ocean Territory",
    "abbreviation": "IO"
  },
  {
    "country": "Brunei",
    "abbreviation": "BN"
  },
  {
    "country": "Bulgaria",
    "abbreviation": "BG"
  },
  {
    "country": "Burkina Faso",
    "abbreviation": "BF"
  },
  {
    "country": "Burundi",
    "abbreviation": "BI"
  },
  {
    "country": "Cambodia",
    "abbreviation": "KH"
  },
  {
    "country": "Cameroon",
    "abbreviation": "CM"
  },
  {
    "country": "Canada",
    "abbreviation": "CA"
  },
  {
    "country": "Cape Verde",
    "abbreviation": "CV"
  },
  {
    "country": "Cayman Islands",
    "abbreviation": "KY"
  },
  {
    "country": "Central African Republic",
    "abbreviation": "CF"
  },
  {
    "country": "Chad",
    "abbreviation": "TD"
  },
  {
    "country": "Chile",
    "abbreviation": "CL"
  },
  {
    "country": "China",
    "abbreviation": "CN"
  },
  {
    "country": "Christmas Island",
    "abbreviation": "CX"
  },
  {
    "country": "Cocos (Keeling) Islands",
    "abbreviation": "CC"
  },
  {
    "country": "Colombia",
    "abbreviation": "CO"
  },
  {
    "country": "Comoros",
    "abbreviation": "KM"
  },
  {
    "country": "Congo",
    "abbreviation": "CG"
  },
  {
    "country": "Cook Islands",
    "abbreviation": "CK"
  },
  {
    "country": "Costa Rica",
    "abbreviation": "CR"
  },
  {
    "country": "Croatia",
    "abbreviation": "HR"
  },
  {
    "country": "Cuba",
    "abbreviation": "CU"
  },
  {
    "country": "Curaçao",
    "abbreviation": "CW"
  },
  {
    "country": "Cyprus",
    "abbreviation": "CY"
  },
  {
    "country": "Czech Republic",
    "abbreviation": "CZ"
  },
  {
    "country": "Denmark",
    "abbreviation": "DK"
  },
  {
    "country": "Djibouti",
    "abbreviation": "DJ"
  },
  {
    "country": "Dominica",
    "abbreviation": "DM"
  },
  {
    "country": "Dominican Republic",
    "abbreviation": "DO"
  },
  {
    "country": "East Timor",
    "abbreviation": "TP"
  },
  {
    "country": "Ecuador",
    "abbreviation": "EC"
  },
  {
    "country": "Egypt",
    "abbreviation": "EG"
  },
  {
    "country": "El Salvador",
    "abbreviation": "SV"
  },
  {
    "country": "Equatorial Guinea",
    "abbreviation": "GQ"
  },
  {
    "country": "Eritrea",
    "abbreviation": "ER"
  },
  {
    "country": "Estonia",
    "abbreviation": "EE"
  },
  {
    "country": "Ethiopia",
    "abbreviation": "ET"
  },
  {
    "country": "Falkland Islands",
    "abbreviation": "FK"
  },
  {
    "country": "Faroe Islands",
    "abbreviation": "FO"
  },
  {
    "country": "Fiji Islands",
    "abbreviation": "FJ"
  },
  {
    "country": "Finland",
    "abbreviation": "FI"
  },
  {
    "country": "France",
    "abbreviation": "FR"
  },
  {
    "country": "French Guiana",
    "abbreviation": "GF"
  },
  {
    "country": "French Polynesia",
    "abbreviation": "PF"
  },
  {
    "country": "French Southern territories",
    "abbreviation": "TF"
  },
  {
    "country": "Gabon",
    "abbreviation": "GA"
  },
  {
    "country": "Gambia",
    "abbreviation": "GM"
  },
  {
    "country": "Georgia",
    "abbreviation": "GE"
  },
  {
    "country": "Germany",
    "abbreviation": "DE"
  },
  {
    "country": "Ghana",
    "abbreviation": "GH"
  },
  {
    "country": "Gibraltar",
    "abbreviation": "GI"
  },
  {
    "country": "Greece",
    "abbreviation": "GR"
  },
  {
    "country": "Greenland",
    "abbreviation": "GL"
  },
  {
    "country": "Grenada",
    "abbreviation": "GD"
  },
  {
    "country": "Guadeloupe",
    "abbreviation": "GP"
  },
  {
    "country": "Guam",
    "abbreviation": "GU"
  },
  {
    "country": "Guatemala",
    "abbreviation": "GT"
  },
  {
    "country": "Guernsey",
    "abbreviation": "GG"
  },
  {
    "country": "Guinea",
    "abbreviation": "GN"
  },
  {
    "country": "Guinea-Bissau",
    "abbreviation": "GW"
  },
  {
    "country": "Guyana",
    "abbreviation": "GY"
  },
  {
    "country": "Haiti",
    "abbreviation": "HT"
  },
  {
    "country": "Heard Island and McDonald Islands",
    "abbreviation": "HM"
  },
  {
    "country": "Holy See (Vatican City State)",
    "abbreviation": "VA"
  },
  {
    "country": "Honduras",
    "abbreviation": "HN"
  },
  {
    "country": "Hong Kong",
    "abbreviation": "HK"
  },
  {
    "country": "Hungary",
    "abbreviation": "HU"
  },
  {
    "country": "Iceland",
    "abbreviation": "IS"
  },
  {
    "country": "India",
    "abbreviation": "IN"
  },
  {
    "country": "Indonesia",
    "abbreviation": "ID"
  },
  {
    "country": "Iran",
    "abbreviation": "IR"
  },
  {
    "country": "Iraq",
    "abbreviation": "IQ"
  },
  {
    "country": "Ireland",
    "abbreviation": "IE"
  },
  {
    "country": "Isle of Man",
    "abbreviation": "IM"
  },
  {
    "country": "Israel",
    "abbreviation": "IL"
  },
  {
    "country": "Italy",
    "abbreviation": "IT"
  },
  {
    "country": "Ivory Coast",
    "abbreviation": "CI"
  },
  {
    "country": "Jamaica",
    "abbreviation": "JM"
  },
  {
    "country": "Japan",
    "abbreviation": "JP"
  },
  {
    "country": "Jersey",
    "abbreviation": "JE"
  },
  {
    "country": "Jordan",
    "abbreviation": "JO"
  },
  {
    "country": "Kazakhstan",
    "abbreviation": "KZ"
  },
  {
    "country": "Kenya",
    "abbreviation": "KE"
  },
  {
    "country": "Kiribati",
    "abbreviation": "KI"
  },
  {
    "country": "Kuwait",
    "abbreviation": "KW"
  },
  {
    "country": "Kyrgyzstan",
    "abbreviation": "KG"
  },
  {
    "country": "Laos",
    "abbreviation": "LA"
  },
  {
    "country": "Latvia",
    "abbreviation": "LV"
  },
  {
    "country": "Lebanon",
    "abbreviation": "LB"
  },
  {
    "country": "Lesotho",
    "abbreviation": "LS"
  },
  {
    "country": "Liberia",
    "abbreviation": "LR"
  },
  {
    "country": "Libyan Arab Jamahiriya",
    "abbreviation": "LY"
  },
  {
    "country": "Liechtenstein",
    "abbreviation": "LI"
  },
  {
    "country": "Lithuania",
    "abbreviation": "LT"
  },
  {
    "country": "Luxembourg",
    "abbreviation": "LU"
  },
  {
    "country": "Macao",
    "abbreviation": "MO"
  },
  {
    "country": "North Macedonia",
    "abbreviation": "MK"
  },
  {
    "country": "Madagascar",
    "abbreviation": "MG"
  },
  {
    "country": "Malawi",
    "abbreviation": "MW"
  },
  {
    "country": "Malaysia",
    "abbreviation": "MY"
  },
  {
    "country": "Maldives",
    "abbreviation": "MV"
  },
  {
    "country": "Mali",
    "abbreviation": "ML"
  },
  {
    "country": "Malta",
    "abbreviation": "MT"
  },
  {
    "country": "Marshall Islands",
    "abbreviation": "MH"
  },
  {
    "country": "Martinique",
    "abbreviation": "MQ"
  },
  {
    "country": "Mauritania",
    "abbreviation": "MR"
  },
  {
    "country": "Mauritius",
    "abbreviation": "MU"
  },
  {
    "country": "Mayotte",
    "abbreviation": "YT"
  },
  {
    "country": "Mexico",
    "abbreviation": "MX"
  },
  {
    "country": "Micronesia, Federated States of",
    "abbreviation": "FM"
  },
  {
    "country": "Moldova",
    "abbreviation": "MD"
  },
  {
    "country": "Monaco",
    "abbreviation": "MC"
  },
  {
    "country": "Mongolia",
    "abbreviation": "MN"
  },
  {
    "country": "Montenegro",
    "abbreviation": "ME"
  },
  {
    "country": "Montserrat",
    "abbreviation": "MS"
  },
  {
    "country": "Morocco",
    "abbreviation": "MA"
  },
  {
    "country": "Mozambique",
    "abbreviation": "MZ"
  },
  {
    "country": "Myanmar",
    "abbreviation": "MM"
  },
  {
    "country": "Namibia",
    "abbreviation": "NA"
  },
  {
    "country": "Nauru",
    "abbreviation": "NR"
  },
  {
    "country": "Nepal",
    "abbreviation": "NP"
  },
  {
    "country": "Netherlands",
    "abbreviation": "NL"
  },
  {
    "country": "Netherlands Antilles",
    "abbreviation": "AN"
  },
  {
    "country": "New Caledonia",
    "abbreviation": "NC"
  },
  {
    "country": "New Zealand",
    "abbreviation": "NZ"
  },
  {
    "country": "Nicaragua",
    "abbreviation": "NI"
  },
  {
    "country": "Niger",
    "abbreviation": "NE"
  },
  {
    "country": "Nigeria",
    "abbreviation": "NG"
  },
  {
    "country": "Niue",
    "abbreviation": "NU"
  },
  {
    "country": "Norfolk Island",
    "abbreviation": "NF"
  },
  {
    "country": "North Korea",
    "abbreviation": "KP"
  },
  {
    "country": "Northern Ireland",
    "abbreviation": "GB"
  },
  {
    "country": "Northern Mariana Islands",
    "abbreviation": "MP"
  },
  {
    "country": "Norway",
    "abbreviation": "NO"
  },
  {
    "country": "Oman",
    "abbreviation": "OM"
  },
  {
    "country": "Pakistan",
    "abbreviation": "PK"
  },
  {
    "country": "Palau",
    "abbreviation": "PW"
  },
  {
    "country": "Palestine",
    "abbreviation": "PS"
  },
  {
    "country": "Panama",
    "abbreviation": "PA"
  },
  {
    "country": "Papua New Guinea",
    "abbreviation": "PG"
  },
  {
    "country": "Paraguay",
    "abbreviation": "PY"
  },
  {
    "country": "Peru",
    "abbreviation": "PE"
  },
  {
    "country": "Philippines",
    "abbreviation": "PH"
  },
  {
    "country": "Pitcairn",
    "abbreviation": "PN"
  },
  {
    "country": "Poland",
    "abbreviation": "PL"
  },
  {
    "country": "Portugal",
    "abbreviation": "PT"
  },
  {
    "country": "Puerto Rico",
    "abbreviation": "PR"
  },
  {
    "country": "Qatar",
    "abbreviation": "QA"
  },
  {
    "country": "Reunion",
    "abbreviation": "RE"
  },
  {
    "country": "Romania",
    "abbreviation": "RO"
  },
  {
    "country": "Russian Federation",
    "abbreviation": "RU"
  },
  {
    "country": "Rwanda",
    "abbreviation": "RW"
  },
  {
    "country": "Saint Barthélemy",
    "abbreviation": "BL"
  },
  {
    "country": "Saint Helena",
    "abbreviation": "SH"
  },
  {
    "country": "Saint Kitts and Nevis",
    "abbreviation": "KN"
  },
  {
    "country": "Saint Lucia",
    "abbreviation": "LC"
  },
  {
    "country": "Saint Martin (French part)",
    "abbreviation": "MF"
  },
  {
    "country": "Saint Pierre and Miquelon",
    "abbreviation": "PM"
  },
  {
    "country": "Saint Vincent and the Grenadines",
    "abbreviation": "VC"
  },
  {
    "country": "Samoa",
    "abbreviation": "WS"
  },
  {
    "country": "San Marino",
    "abbreviation": "SM"
  },
  {
    "country": "Sao Tome and Principe",
    "abbreviation": "ST"
  },
  {
    "country": "Saudi Arabia",
    "abbreviation": "SA"
  },
  {
    "country": "Senegal",
    "abbreviation": "SN"
  },
  {
    "country": "Serbia",
    "abbreviation": "RS"
  },
  {
    "country": "Seychelles",
    "abbreviation": "SC"
  },
  {
    "country": "Sierra Leone",
    "abbreviation": "SL"
  },
  {
    "country": "Singapore",
    "abbreviation": "SG"
  },
  {
    "country": "Sint Maarten (Dutch part)",
    "abbreviation": "SX"
  },
  {
    "country": "Slovakia",
    "abbreviation": "SK"
  },
  {
    "country": "Slovenia",
    "abbreviation": "SI"
  },
  {
    "country": "Solomon Islands",
    "abbreviation": "SB"
  },
  {
    "country": "Somalia",
    "abbreviation": "SO"
  },
  {
    "country": "South Africa",
    "abbreviation": "ZA"
  },
  {
    "country": "South Georgia and the South Sandwich Islands",
    "abbreviation": "GS"
  },
  {
    "country": "South Korea",
    "abbreviation": "KR"
  },
  {
    "country": "South Sudan",
    "abbreviation": "SS"
  },
  {
    "country": "Spain",
    "abbreviation": "ES"
  },
  {
    "country": "Sri Lanka",
    "abbreviation": "LK"
  },
  {
    "country": "Sudan",
    "abbreviation": "SD"
  },
  {
    "country": "Suriname",
    "abbreviation": "SR"
  },
  {
    "country": "Svalbard and Jan Mayen",
    "abbreviation": "SJ"
  },
  {
    "country": "Swaziland",
    "abbreviation": "SZ"
  },
  {
    "country": "Sweden",
    "abbreviation": "SE"
  },
  {
    "country": "Switzerland",
    "abbreviation": "CH"
  },
  {
    "country": "Syria",
    "abbreviation": "SY"
  },
  {
    "country": "Tajikistan",
    "abbreviation": "TJ"
  },
  {
    "country": "Taiwan",
    "abbreviation": "TW"
  },
  {
    "country": "Tanzania",
    "abbreviation": "TZ"
  },
  {
    "country": "Thailand",
    "abbreviation": "TH"
  },
  {
    "country": "The Democratic Republic of Congo",
    "abbreviation": "CD"
  },
  {
    "country": "Timor-Leste",
    "abbreviation": "TL"
  },
  {
    "country": "Togo",
    "abbreviation": "TG"
  },
  {
    "country": "Tokelau",
    "abbreviation": "TK"
  },
  {
    "country": "Tonga",
    "abbreviation": "TO"
  },
  {
    "country": "Trinidad and Tobago",
    "abbreviation": "TT"
  },
  {
    "country": "Tunisia",
    "abbreviation": "TN"
  },
  {
    "country": "Turkey",
    "abbreviation": "TR"
  },
  {
    "country": "Turkmenistan",
    "abbreviation": "TM"
  },
  {
    "country": "Turks and Caicos Islands",
    "abbreviation": "TC"
  },
  {
    "country": "Tuvalu",
    "abbreviation": "TV"
  },
  {
    "country": "Uganda",
    "abbreviation": "UG"
  },
  {
    "country": "Ukraine",
    "abbreviation": "UA"
  },
  {
    "country": "United Arab Emirates",
    "abbreviation": "AE"
  },
  {
    "country": "United Kingdom",
    "abbreviation": "GB"
  },
  {
    "country": "United States",
    "abbreviation": "US"
  },
  {
    "country": "United States Minor Outlying Islands",
    "abbreviation": "UM"
  },
  {
    "country": "Uruguay",
    "abbreviation": "UY"
  },
  {
    "country": "Uzbekistan",
    "abbreviation": "UZ"
  },
  {
    "country": "Vanuatu",
    "abbreviation": "VU"
  },
  {
    "country": "Venezuela",
    "abbreviation": "VE"
  },
  {
    "country": "Vietnam",
    "abbreviation": "VN"
  },
  {
    "country": "Virgin Islands, British",
    "abbreviation": "VG"
  },
  {
    "country": "Virgin Islands, U.S.",
    "abbreviation": "VI"
  },
  {
    "country": "Wallis and Futuna",
    "abbreviation": "WF"
  },
  {
    "country": "Western Sahara",
    "abbreviation": "EH"
  },
  {
    "country": "Yemen",
    "abbreviation": "YE"
  },
  {
    "country": "Yugoslavia",
    "abbreviation": "YU"
  },
  {
    "country": "Zambia",
    "abbreviation": "ZM"
  },
  {
    "country": "Zimbabwe",
    "abbreviation": "ZW"
  }
];

export default CountryCodes;
