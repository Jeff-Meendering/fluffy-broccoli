use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;

use phonenumber::country;
use regex::Regex;

use super::normalize::DetectionText;
use super::{EntitySpan, crypto, national_ids};
use crate::EntityType;

fn compile(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(error) => panic!("invalid built-in detector regex {pattern:?}: {error}"),
    }
}

macro_rules! regex {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| compile($pattern));
    };
}

const MONTHS: &str = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)";
regex!(
    LABELLED_NAME,
    r"(?im)\bFull[ \t]+name[ \t]*:[ \t]*(?P<value>[\p{L}][\p{L}\p{M}.'’ \t-]{0,100}?)[ \t]*(?:\||\r?$)"
);
regex!(
    LABELLED_PERSON_NAME,
    r"(?im)(?:^[ \t]*name|\b(?:full|first|last|contact|patient|employee|customer|applicant|member|legal|your|my)[ \t]+name|\b(?:surname|family[ \t]+name|given[ \t]+name|attn|attention|employee|customer|patient|applicant|cardholder|account[ \t]+holder|beneficiary|borrower|insured|tenant|claimant|signed|prepared[ \t]+by))[ \t]*:[ \t]*(?P<value>[\p{Lu}][\p{L}\p{M}'’.-]*(?:[ \t]+[\p{Lu}][\p{L}\p{M}'’.-]*){1,4})[ \t]*(?:[|<(,]|\r?$)"
);
regex!(
    EMAIL,
    r"[\w.!#$%&'*+/=?^`{|}~@-]+@(?:[\p{L}\p{M}0-9_-]+\.)+(?:(?i:xn--)[A-Za-z0-9-]{1,59}|[\p{L}\p{M}]{2,63})"
);
regex!(
    EMAIL_ASSIGNMENT,
    r"(?i)\A(?:email|e-mail|mail|user|username|value|contact)="
);
regex!(SSN_DASHED, r"[0-9]{3}-[0-9]{2}-[0-9]{4}");
regex!(
    SSN_LABELLED,
    r"(?i)\b(?:ssn|social[ _\t]+security)(?:[ _\t]+(?:number|no\.?))?(?:[ \t]+(?:[:=#][ \t]*)?|[:=#][ \t]*)(?P<value>[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4})"
);
regex!(SSN_SPACED, r"[0-9]{3} [0-9]{2} [0-9]{4}");
regex!(CARD, r"(?:[0-9][ -]?){12,18}[0-9]");
regex!(
    IP_ADDRESS,
    r"[A-Fa-f0-9]*:[A-Fa-f0-9:]+(?:(?:\.[0-9]+){3})?(?:%[0-9]+)?|(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
);
regex!(
    DOB_NUMERIC_VALUE,
    r"([0-9]{1,4})[-/.]([0-9]{1,2})[-/.]([0-9]{1,4})"
);
regex!(
    DOB_DAY_MONTH_VALUE,
    r"(?i)([0-9]{1,2})(?:st|nd|rd|th)?[-/ .]*([a-z]+)\.?,?[-/ .]*([0-9]{2,4})"
);
regex!(
    DOB_MONTH_DAY_VALUE,
    r"(?i)([a-z]+)\.?[ .]*([0-9]{1,2})(?:st|nd|rd|th)?,?[ .]*([0-9]{2,4})"
);
regex!(
    ADDRESS_EN,
    concat!(
        r"(?i)\b[0-9]{1,6}[a-z]?\s+(?-i:[\p{Lu}\d])[\p{L}\d.'’-]*\s+(?:[\p{L}\d][\p{L}\d.'’-]*\s+){0,4}",
        r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|place|pl|way|terrace|ter|circle|cir|parkway|pkwy|highway|hwy|square|sq|trail|trl|loop|alley|crescent|cres|close|gardens|grove|row|walk|plaza|path|pike|turnpike|route|rte|broadway|expressway|expy|freeway|fwy)\b",
        r"\.?(?:,?\s+(?:n|s|e|w|ne|nw|se|sw|north|south|east|west)\b\.?)?(?:,?\s+(?:apt|apartment|suite|ste|unit|floor|fl|bldg|building|#)\.?\s*#?\s*[\w-]{1,8}\b)?"
    )
);
regex!(
    ADDRESS_PO_BOX,
    r"(?i)\b(?:p\.?\s?o\.?\s+box|post\s+office\s+box|pob)\s*#?\s*[0-9]{1,6}"
);
regex!(
    ADDRESS_FR,
    r"(?i)\b(?P<value>[0-9]{1,4}(?:\s?(?:bis|ter))?,?\s+(?:rue|avenue|boulevard|bd|place|chemin|allée|allee|impasse|quai|cours|passage)\s+[\p{L}][\p{L}'’-]*(?:[ \t]+[\p{L}][\p{L}'’-]*){0,5})(?:[,.;\r\n]|[ \t]+[0-9]|[ \t]*$)"
);
regex!(
    ADDRESS_DE,
    r"(?i)\b[\p{L}][\p{L}-]{2,}(?:straße|strasse|str\.|weg|platz|allee|gasse|damm|ufer|laan|straat|gatan|vägen|vej|gade)\s+[0-9]{1,4}\s?[a-z]?"
);
regex!(
    ADDRESS_ROMANCE,
    r"\b(?:Calle|Avenida|Avda\.?|Paseo|Plaza|Carrer|Via|Viale|Piazza|Corso|Rua|Praça)\s+(?:[\p{Lu}][\p{L}'’-]*\s+){1,5}?(?:n[º°.]?\s*)?[0-9]{1,4}"
);
regex!(
    UK_NI,
    r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?[0-9]{2}\s?[0-9]{2}\s?[0-9]{2}\s?[A-D]\b"
);
regex!(IBAN_PREFIX, r"[A-Za-z]{2}[0-9]{2}");
regex!(
    LABELLED_ID,
    r"(?i)\b(?:(?:passport|driver['’]?s?[ \t]+licen[cs]e|driving[ \t]+licen[cs]e)(?:[ \t]+(?:number|no\.?))?|account[ \t]+(?:number|no\.?)|routing[ \t]+(?:number|no\.?)|tax[ \t]+id|national[ \t]+id(?:[ \t]+(?:number|no\.?))?|id[ \t]+number|medical[ \t]+record[ \t]+(?:number|no\.?)|mrn|patient[ \t]+(?:id|number)|member[ \t]+(?:id|number)|policy[ \t]+(?:number|no\.?))[ \t]*[:=#][ \t]*[A-Z0-9](?:[A-Z0-9-]|[ \t][0-9]){3,24}[A-Z0-9]"
);
regex!(
    MAC,
    r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}"
);
regex!(AWS_KEY, r"(?:AKIA|ASIA)[A-Z0-9]{16}");
regex!(
    GITHUB_TOKEN,
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b"
);
regex!(SLACK_TOKEN, r"\bxox[abpors]-[A-Za-z0-9-]{10,250}");
regex!(GOOGLE_KEY, r"\bAIza[0-9A-Za-z_-]{35}");
regex!(STRIPE_KEY, r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,99}\b");
regex!(
    PRIVATE_KEY,
    r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----"
);
regex!(
    JWT,
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
);
regex!(
    SECRET,
    r#"(?i)[\w.-]{0,20}?(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)[ \t]*[:=][ \t]*[\"']?(?P<value>[^\s\"'<>,;]{8,128})"#
);
regex!(BITCOIN, r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}");
regex!(BECH32_ADDRESS, r"(?i)(?:bc|tb)1[ac-hj-np-z02-9]{11,87}");
regex!(ETHEREUM, r"0x[0-9a-fA-F]{40}");
regex!(CPF, r"[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}");
regex!(AADHAAR, r"[2-9][0-9]{3}[ -][0-9]{4}[ -][0-9]{4}");
regex!(
    NHS,
    r"(?i)\bNHS(?:[ \t]+(?:number|no\.?))?[ \t]*[:#=]?[ \t]*(?P<value>[0-9]{3}[ -]?[0-9]{3}[ -]?[0-9]{4})"
);
regex!(SIN, r"[0-9]{3}[ -][0-9]{3}[ -][0-9]{3}");
regex!(DNI, r"(?:[0-9]{8}|[XYZ][0-9]{7})[- ]?[A-Z]");
regex!(
    CODICE_FISCALE,
    r"[A-Z]{6}[0-9]{2}[A-EHLMPRST][0-9]{2}[A-Z][0-9]{3}[A-Z]"
);
regex!(PESEL, r"[0-9]{11}");
regex!(
    NIR,
    r"[12] ?[0-9]{2} ?(?:0[1-9]|1[0-2]) ?(?:[0-9]{2}|2[AB]) ?[0-9]{3} ?[0-9]{3} ?[0-9]{2}"
);
regex!(PERSONNUMMER, r"(?:[0-9]{2})?[0-9]{6}[-+][0-9]{4}");
regex!(
    BSN,
    r"(?i)\bBSN(?:[ \t]+(?:number|nummer))?[ \t]*[:#=]?[ \t]*(?P<value>[0-9]{9})"
);
regex!(
    TFN,
    r"(?i)\bTFN(?:[ \t]+(?:number|no\.?))?[ \t]*[:#=]?[ \t]*(?P<value>[0-9]{3}[ -]?[0-9]{3}[ -]?[0-9]{2,3})"
);
regex!(SOUTH_AFRICA, r"[0-9]{13}");
regex!(RRN, r"[0-9]{6}-[1-8][0-9]{6}");
regex!(CHINA_ID, r"[0-9]{17}[0-9X]");

regex!(
    PHONE_CANDIDATE,
    r"\+?\(?[0-9][0-9 ().-]{5,28}[0-9](?:\s*(?:ext\.?|extension|x|#)\s*[0-9]{1,6})?"
);
regex!(DOTTED_QUAD, r"\A[0-9]{1,3}(?:\.[0-9]{1,3}){3}\z");
regex!(ISO_DATE, r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z");
regex!(
    NON_PHONE_LABEL,
    r"(?i)\b(?:nhs[ \t]+(?:number|no\.?)|bsn(?:[ \t]+(?:number|nummer))?|tfn(?:[ \t]+(?:number|no\.?))?|(?:cpf|cnpj|iban|imei)(?:[ \t]+(?:number|no\.?))?|ssn|social[ \t]+security(?:[ \t]+number)?)[ \t]*[:=#]?[ \t]*$"
);

#[derive(Clone, Copy)]
enum Gate {
    Always,
    At,
    Ip,
    Mac,
    Any(&'static [&'static str]),
}

#[derive(Clone, Copy)]
enum Boundary {
    None,
    Email,
    WordHyphen,
    Cpf,
    Card,
    Ipv6,
    Ipv4,
    Ip,
    Address,
    Date,
    LabelledIdentifier,
    Mac,
    Aws,
    Google,
    Jwt,
    AsciiAlnum,
    Secret,
}

type Validator = fn(&str, usize, &str) -> f32;

struct Rule {
    kind: EntityType,
    pattern: &'static LazyLock<Regex>,
    score: f32,
    validator: Option<Validator>,
    value_only: bool,
    min_digits: usize,
    gate: Gate,
    method: &'static str,
    boundary: Boundary,
}

impl Rule {
    const fn new(kind: EntityType, pattern: &'static LazyLock<Regex>, score: f32) -> Self {
        Self {
            kind,
            pattern,
            score,
            validator: None,
            value_only: false,
            min_digits: 0,
            gate: Gate::Always,
            method: "Pattern",
            boundary: Boundary::None,
        }
    }

    const fn validate(mut self, validator: Validator) -> Self {
        self.validator = Some(validator);
        self
    }

    const fn value(mut self) -> Self {
        self.value_only = true;
        self
    }

    const fn digits(mut self, count: usize) -> Self {
        self.min_digits = count;
        self
    }

    const fn when(mut self, gate: Gate) -> Self {
        self.gate = gate;
        self
    }

    const fn method(mut self, method: &'static str) -> Self {
        self.method = method;
        self
    }

    const fn bounds(mut self, boundary: Boundary) -> Self {
        self.boundary = boundary;
        self
    }
}

const NAME_LABELS: &[&str] = &[
    "name",
    "attn",
    "attention",
    "employee",
    "customer",
    "patient",
    "applicant",
    "holder",
    "beneficiary",
    "borrower",
    "insured",
    "tenant",
    "claimant",
    "signed",
    "prepared",
];
const DOB_LABELS: &[&str] = &["birth", "dob", "born", "d.o.b"];
const ID_LABELS: &[&str] = &[
    "passport", "licen", "account", "routing", "tax", "id", "mrn", "medical", "patient", "member",
    "policy",
];
const SECRET_LABELS: &[&str] = &["pass", "secret", "key", "token"];

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let mut rules = Vec::with_capacity(44);
    rules.push(
        Rule::new(EntityType::Person, &LABELLED_NAME, 0.85)
            .value()
            .when(Gate::Any(&["full"])),
    );
    rules.push(
        Rule::new(EntityType::Person, &LABELLED_PERSON_NAME, 0.70)
            .value()
            .when(Gate::Any(NAME_LABELS)),
    );
    rules.push(
        Rule::new(EntityType::Email, &EMAIL, 0.99)
            .validate(email)
            .when(Gate::At)
            .bounds(Boundary::Email),
    );
    rules.push(
        Rule::new(EntityType::SocialSecurityNumber, &SSN_DASHED, 0.8)
            .validate(ssn_dashed)
            .digits(9)
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::SocialSecurityNumber, &SSN_LABELLED, 0.9)
            .validate(ssn_labelled)
            .value()
            .digits(9)
            .when(Gate::Any(&["ssn", "social"]))
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::SocialSecurityNumber, &SSN_SPACED, 0.55)
            .validate(ssn_spaced)
            .digits(9)
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::PaymentCard, &CARD, 0.9)
            .validate(card)
            .digits(13)
            .bounds(Boundary::Card),
    );
    rules.push(
        Rule::new(EntityType::IpAddress, &IP_ADDRESS, 0.8)
            .validate(ip)
            .when(Gate::Ip)
            .bounds(Boundary::Ip),
    );

    static DOB_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        compile(&format!(
            r"(?i)\b(?:d\.?o\.?b\.?|date[_\s]+of[_\s]+birth|birth[_\s]*date|birthday|born(?:[_\s]+on)?)[_\s]*[:=\-]?\s*(?:[0-9]{{1,4}}[-/.][0-9]{{1,2}}[-/.][0-9]{{1,4}}|[0-9]{{1,2}}(?:st|nd|rd|th)?[-/ .]*{MONTHS}\.?,?[-/ .]*[0-9]{{2,4}}|{MONTHS}\.?[ .]*[0-9]{{1,2}}(?:st|nd|rd|th)?,?[ .]*[0-9]{{2,4}})"
        ))
    });
    rules.push(
        Rule::new(EntityType::DateOfBirth, &DOB_PATTERN, 0.9)
            .validate(date_of_birth)
            .digits(4)
            .when(Gate::Any(DOB_LABELS))
            .bounds(Boundary::Date),
    );
    rules.push(
        Rule::new(EntityType::StreetAddress, &ADDRESS_EN, 0.8)
            .digits(1)
            .bounds(Boundary::Address),
    );
    rules.push(
        Rule::new(EntityType::StreetAddress, &ADDRESS_PO_BOX, 0.8)
            .digits(1)
            .when(Gate::Any(&["box", "pob"]))
            .bounds(Boundary::Address),
    );
    rules.push(
        Rule::new(EntityType::StreetAddress, &ADDRESS_FR, 0.7)
            .value()
            .digits(1),
    );
    rules.push(
        Rule::new(EntityType::StreetAddress, &ADDRESS_DE, 0.65)
            .digits(1)
            .bounds(Boundary::Address),
    );
    rules.push(
        Rule::new(EntityType::StreetAddress, &ADDRESS_ROMANCE, 0.65)
            .digits(1)
            .bounds(Boundary::Address),
    );
    rules.push(Rule::new(EntityType::UkNationalInsurance, &UK_NI, 0.8).digits(6));
    rules.push(
        Rule::new(EntityType::Iban, &IBAN_PREFIX, 0.95)
            .validate(|_, _, value| if iban(value) { 0.95 } else { 0.0 })
            .digits(2),
    );
    rules.push(
        Rule::new(EntityType::LabelledIdentifier, &LABELLED_ID, 0.65)
            .validate(labelled_identifier)
            .digits(1)
            .when(Gate::Any(ID_LABELS))
            .bounds(Boundary::LabelledIdentifier),
    );
    rules.push(
        Rule::new(EntityType::MacAddress, &MAC, 0.7)
            .validate(mac)
            .when(Gate::Mac)
            .bounds(Boundary::Mac),
    );
    rules.push(
        Rule::new(EntityType::Credential, &AWS_KEY, 0.9)
            .when(Gate::Any(&["AKIA", "ASIA"]))
            .method("Pattern (AWS access key)")
            .bounds(Boundary::Aws),
    );
    rules.push(
        Rule::new(EntityType::Credential, &GITHUB_TOKEN, 0.95)
            .when(Gate::Any(&["gh"]))
            .method("Pattern (GitHub token)"),
    );
    rules.push(
        Rule::new(EntityType::Credential, &SLACK_TOKEN, 0.9)
            .when(Gate::Any(&["xox"]))
            .method("Pattern (Slack token)"),
    );
    rules.push(
        Rule::new(EntityType::Credential, &GOOGLE_KEY, 0.9)
            .when(Gate::Any(&["AIza"]))
            .method("Pattern (Google API key)")
            .bounds(Boundary::Google),
    );
    rules.push(
        Rule::new(EntityType::Credential, &STRIPE_KEY, 0.9)
            .when(Gate::Any(&["k_live", "k_test"]))
            .method("Pattern (Stripe key)"),
    );
    rules.push(
        Rule::new(EntityType::Credential, &PRIVATE_KEY, 0.95)
            .when(Gate::Any(&["PRIVATE KEY"]))
            .method("Pattern (private key)"),
    );
    rules.push(
        Rule::new(EntityType::Credential, &JWT, 0.85)
            .when(Gate::Any(&["eyJ"]))
            .method("Pattern (JSON Web Token)")
            .bounds(Boundary::Jwt),
    );
    rules.push(
        Rule::new(EntityType::Credential, &SECRET, 0.6)
            .validate(secret)
            .value()
            .when(Gate::Any(SECRET_LABELS))
            .method("Pattern (labelled secret)")
            .bounds(Boundary::Secret),
    );
    rules.push(
        Rule::new(EntityType::CryptoWallet, &BITCOIN, 0.95)
            .validate(|_, _, value| crypto::bitcoin(value))
            .method("Pattern (Bitcoin address)")
            .bounds(Boundary::AsciiAlnum),
    );
    rules.push(
        Rule::new(EntityType::CryptoWallet, &BECH32_ADDRESS, 0.95)
            .validate(|_, _, value| crypto::bech32(value))
            .when(Gate::Any(&["bc1", "tb1"]))
            .method("Pattern (Bitcoin address)")
            .bounds(Boundary::AsciiAlnum),
    );
    rules.push(
        Rule::new(EntityType::CryptoWallet, &ETHEREUM, 0.95)
            .validate(|_, _, value| crypto::ethereum(value))
            .when(Gate::Any(&["0x"]))
            .method("Pattern (Ethereum address)")
            .bounds(Boundary::AsciiAlnum),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &CPF, 0.9)
            .validate(national_ids::cpf)
            .digits(11)
            .method("Pattern (Brazil CPF)")
            .bounds(Boundary::Cpf),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &AADHAAR, 0.85)
            .validate(national_ids::aadhaar)
            .digits(12)
            .method("Pattern (India Aadhaar)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &NHS, 0.85)
            .validate(national_ids::nhs)
            .value()
            .digits(10)
            .when(Gate::Any(&["nhs"]))
            .method("Pattern (UK NHS number)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &SIN, 0.6)
            .validate(national_ids::sin)
            .digits(9)
            .method("Pattern (Canada SIN)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &DNI, 0.85)
            .validate(national_ids::dni)
            .digits(7)
            .method("Pattern (Spain DNI/NIE)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &CODICE_FISCALE, 0.9)
            .validate(national_ids::codice_fiscale)
            .digits(7)
            .method("Pattern (Italy codice fiscale)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &PESEL, 0.7)
            .validate(national_ids::pesel)
            .digits(11)
            .method("Pattern (Poland PESEL)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &NIR, 0.9)
            .validate(national_ids::nir)
            .digits(13)
            .method("Pattern (France NIR)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &PERSONNUMMER, 0.8)
            .validate(national_ids::personnummer)
            .digits(10)
            .method("Pattern (Sweden personnummer)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &BSN, 0.85)
            .validate(national_ids::bsn)
            .value()
            .digits(9)
            .when(Gate::Any(&["bsn"]))
            .method("Pattern (Netherlands BSN)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &TFN, 0.85)
            .validate(national_ids::tfn)
            .value()
            .digits(8)
            .when(Gate::Any(&["tfn"]))
            .method("Pattern (Australia TFN)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &SOUTH_AFRICA, 0.65)
            .validate(national_ids::south_africa)
            .digits(13)
            .method("Pattern (South Africa ID)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &RRN, 0.85)
            .validate(national_ids::rrn)
            .digits(13)
            .method("Pattern (Korea RRN)")
            .bounds(Boundary::WordHyphen),
    );
    rules.push(
        Rule::new(EntityType::NationalId, &CHINA_ID, 0.85)
            .validate(national_ids::china_id)
            .digits(17)
            .method("Pattern (China resident ID)")
            .bounds(Boundary::WordHyphen),
    );
    rules
});

/// Fast, deterministic, non-model entity detection over UTF-8 text.
///
/// Returned `start` and `length` are exact byte offsets into the input passed to
/// [`detect`](Self::detect). The detector is immutable after construction and can be
/// shared between threads.
#[derive(Debug, Clone)]
pub struct PatternDetector {
    phone_regions: Vec<country::Id>,
    phone_region_names: Vec<String>,
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::with_phone_regions(["US", "GB"])
    }
}

impl PatternDetector {
    /// Construct a detector with configured ISO country regions.
    ///
    /// Use [`Default::default`] for the legacy US/GB configuration.
    ///
    /// Items may be individual region names or comma-separated lists. Names are trimmed,
    /// uppercased, deduplicated, and checked against phonenumber's metadata. Invalid names
    /// are ignored. As in the legacy engine, an empty valid set falls back to US.
    #[must_use]
    pub fn new<I, S>(regions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::with_phone_regions(regions)
    }

    /// Construct a detector with configured ISO country regions.
    ///
    /// Items may be individual region names or comma-separated lists. Names are trimmed,
    /// uppercased, deduplicated, and checked against phonenumber's metadata. Invalid names
    /// are ignored. As in the legacy engine, an empty valid set falls back to US.
    #[must_use]
    pub fn with_phone_regions<I, S>(regions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut phone_regions = Vec::new();
        let mut phone_region_names = Vec::new();
        for item in regions {
            for region in item.as_ref().split(',') {
                let name = region.trim().to_ascii_uppercase();
                if name.is_empty()
                    || phone_region_names.contains(&name)
                    || phonenumber::metadata::DATABASE.by_id(&name).is_none()
                {
                    continue;
                }
                let Ok(id) = country::Id::from_str(&name) else {
                    continue;
                };
                phone_regions.push(id);
                phone_region_names.push(name);
            }
        }
        if phone_regions.is_empty() {
            phone_regions.push(country::US);
            phone_region_names.push("US".to_owned());
        }
        Self {
            phone_regions,
            phone_region_names,
        }
    }

    #[must_use]
    pub fn phone_regions(&self) -> &[String] {
        &self.phone_region_names
    }

    /// Detect all supported non-model entity families and resolve nested overlaps.
    #[must_use]
    pub fn detect(&self, text: &str) -> Vec<EntitySpan> {
        let view = DetectionText::new(text);
        let normalized = view.text();
        let digits = normalized
            .bytes()
            .filter(|byte| byte.is_ascii_digit())
            .count();
        let mut spans = Vec::new();

        for rule in RULES.iter() {
            if digits < rule.min_digits || !gate_matches(rule.gate, normalized, digits) {
                continue;
            }
            for captures in rule.pattern.captures_iter(normalized) {
                let Some(whole) = captures.get(0) else {
                    continue;
                };
                if !boundary_matches(rule.boundary, normalized, whole.start(), whole.end()) {
                    continue;
                }
                let selected = if rule.value_only {
                    captures.name("value").or(Some(whole))
                } else {
                    Some(whole)
                };
                let Some(selected) = selected else { continue };
                let mut start = selected.start();
                let mut length = selected.len();
                let mut candidate = selected.as_str();

                if rule.kind == EntityType::Iban {
                    let Some(candidate_length) = iban_candidate_length(normalized, start) else {
                        continue;
                    };
                    length = candidate_length;
                    candidate = &normalized[start..start + length];
                }
                if rule.kind == EntityType::Email
                    && let Some(assignment) = EMAIL_ASSIGNMENT.find(candidate)
                {
                    start += assignment.end();
                    length -= assignment.len();
                    candidate = &candidate[assignment.end()..];
                }
                if rule.kind == EntityType::Credential && rule.method == "Pattern (labelled secret)"
                {
                    // Validate and report the same trimmed value. The legacy implementation
                    // validated a temporary trim but accidentally retained punctuation in its span.
                    let trimmed = candidate.trim_end_matches(['.', '!', '?', ')', ']', '}']);
                    length = trimmed.len();
                    candidate = trimmed;
                }

                let confidence = rule.validator.map_or(rule.score, |validate| {
                    validate(normalized, start, candidate)
                });
                if confidence > 0.0 {
                    spans.push(EntitySpan::new(
                        rule.kind,
                        start,
                        length,
                        confidence.min(0.99),
                        rule.method,
                    ));
                }
            }
        }

        if digits >= 7 {
            self.detect_phones(normalized, &mut spans);
        }
        Self::resolve(spans)
            .into_iter()
            .map(|span| view.original_span(span))
            .collect()
    }

    /// Resolve identical duplicates and nested findings using confidence and containment.
    /// Exact coincident spans of different entity types are deliberately both retained.
    #[must_use]
    pub fn resolve<I>(spans: I) -> Vec<EntitySpan>
    where
        I: IntoIterator<Item = EntitySpan>,
    {
        let mut ordered: Vec<EntitySpan> = spans.into_iter().collect();
        ordered.sort_by(|left, right| {
            left.start
                .cmp(&right.start)
                .then_with(|| right.length.cmp(&left.length))
                .then_with(|| right.confidence.total_cmp(&left.confidence))
        });
        let mut active: Vec<usize> = Vec::new();
        let mut resolved: Vec<EntitySpan> = Vec::new();
        for span in ordered {
            active.retain(|index| resolved[*index].start + resolved[*index].length > span.start);
            let covered = active.iter().rev().any(|index| {
                let other = &resolved[*index];
                if other.start == span.start
                    && other.length == span.length
                    && other.entity_type == span.entity_type
                {
                    return true;
                }
                other.start <= span.start
                    && other.start + other.length >= span.start + span.length
                    && other.entity_type != span.entity_type
                    && other.confidence >= span.confidence
                    && !(other.start == span.start && other.length == span.length)
            });
            if !covered {
                active.push(resolved.len());
                resolved.push(span);
            }
        }
        resolved
    }

    #[must_use]
    pub fn luhn(text: &str) -> bool {
        luhn(text)
    }

    #[must_use]
    pub fn iban(text: &str) -> bool {
        iban(text)
    }

    #[must_use]
    pub fn ssn_structure_valid(text: &str) -> bool {
        ssn_structure_valid(text)
    }

    fn detect_phones(&self, text: &str, spans: &mut Vec<EntitySpan>) {
        for candidate in PHONE_CANDIDATE.find_iter(text) {
            let start = candidate.start();
            let end = candidate.end();
            if previous_char(text, start).is_some_and(|c| c.is_alphanumeric() || c == '+')
                || next_char(text, end).is_some_and(char::is_alphanumeric)
            {
                continue;
            }
            let value = candidate.as_str();
            // Strict grouping rejects date-like hyphen groups even when their digits happen
            // to form a valid number in a configured country.
            let bytes = value.as_bytes();
            if bytes.len() == 12
                && bytes[4] == b'-'
                && bytes[7] == b'-'
                && bytes
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
            {
                continue;
            }
            let digit_count = value.bytes().filter(|byte| byte.is_ascii_digit()).count();
            if !(7..=17).contains(&digit_count)
                || DOTTED_QUAD.is_match(value)
                || ISO_DATE.is_match(value)
                // Parsing alone accepts punctuation in a Brazilian CPF as a US number.
                // Its 3.3.3-2 grouping is identifier evidence even with a bad check digit.
                || CPF.find(value).is_some_and(|matched| matched.start() == 0 && matched.end() == value.len())
            {
                continue;
            }
            if previous_char(text, start)
                .is_some_and(|c| matches!(c, '/' | '#' | '$' | '£' | '€' | '\\'))
            {
                continue;
            }
            let mut prefix_start = start.saturating_sub(60);
            while !text.is_char_boundary(prefix_start) {
                prefix_start += 1;
            }
            if NON_PHONE_LABEL.is_match(&text[prefix_start..start]) {
                continue;
            }

            if value.starts_with('+') {
                let valid = phonenumber::parse(None, value).is_ok_and(|number| number.is_valid());
                if valid {
                    spans.push(EntitySpan::new(
                        EntityType::Phone,
                        start,
                        value.len(),
                        0.85,
                        "Pattern",
                    ));
                }
                continue;
            }
            for region in &self.phone_regions {
                let valid =
                    phonenumber::parse(Some(*region), value).is_ok_and(|number| number.is_valid());
                let bare = value.bytes().all(|byte| byte.is_ascii_digit());
                if valid && *region == country::US && bare && value.len() == 10 {
                    let bytes = value.as_bytes();
                    if !matches!(bytes[0], b'2'..=b'9') || !matches!(bytes[3], b'2'..=b'9') {
                        continue;
                    }
                }
                if valid && *region == country::GB && bare && !value.starts_with('0') {
                    // Strict GB grouping requires the trunk prefix rather than interpreting
                    // arbitrary ten-digit identifiers as national-significant numbers.
                    continue;
                }
                if valid {
                    spans.push(EntitySpan::new(
                        EntityType::Phone,
                        start,
                        value.len(),
                        if bare { 0.55 } else { 0.85 },
                        "Pattern",
                    ));
                    break;
                }
            }
        }
    }
}

fn gate_matches(gate: Gate, text: &str, digits: usize) -> bool {
    match gate {
        Gate::Always => true,
        Gate::At => text.contains('@'),
        Gate::Ip => text.contains(':') || digits >= 4,
        Gate::Mac => text.contains(':') || text.contains('-') || text.contains('.'),
        Gate::Any(needles) => needles
            .iter()
            .any(|needle| contains_ignore_ascii_case(text, needle)),
    }
}

fn contains_ignore_ascii_case(text: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if !needle.is_ascii() {
        return text.to_lowercase().contains(&needle.to_lowercase());
    }
    let first = needle.as_bytes()[0].to_ascii_lowercase();
    let upper = first.to_ascii_uppercase();
    memchr::memchr2_iter(first, upper, text.as_bytes()).any(|index| {
        text.as_bytes()
            .get(index..index + needle.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(needle.as_bytes()))
    })
}

fn previous_char(text: &str, start: usize) -> Option<char> {
    text.get(..start)?.chars().next_back()
}

fn next_char(text: &str, end: usize) -> Option<char> {
    text.get(end..)?.chars().next()
}

fn is_word(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric() || c == '_'
    } else {
        c.is_alphanumeric() || is_combining_or_connector(c)
    }
}

fn is_combining_or_connector(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036f}' | '\u{0483}'..='\u{0489}' | '\u{0591}'..='\u{05bd}' |
        '\u{05bf}' | '\u{05c1}'..='\u{05c2}' | '\u{05c4}'..='\u{05c5}' | '\u{0610}'..='\u{061a}' |
        '\u{064b}'..='\u{065f}' | '\u{0670}' | '\u{06d6}'..='\u{06ed}' | '\u{0711}' |
        '\u{0730}'..='\u{074a}' | '\u{07a6}'..='\u{07b0}' | '\u{07eb}'..='\u{07f3}' |
        '\u{0816}'..='\u{082d}' | '\u{0859}'..='\u{085b}' | '\u{08d3}'..='\u{0903}' |
        '\u{093a}'..='\u{094f}' | '\u{0951}'..='\u{0957}' | '\u{0962}'..='\u{0963}' |
        '\u{0981}'..='\u{09fe}' | '\u{0a01}'..='\u{0b4d}' | '\u{0b55}'..='\u{0c4d}' |
        '\u{0c55}'..='\u{0d4d}' | '\u{0d62}'..='\u{0d63}' | '\u{0d81}'..='\u{0e4e}' |
        '\u{0e47}'..='\u{0fbc}' | '\u{102b}'..='\u{103e}' | '\u{1056}'..='\u{1059}' |
        '\u{105e}'..='\u{1060}' | '\u{1062}'..='\u{1064}' | '\u{1067}'..='\u{106d}' |
        '\u{1071}'..='\u{1074}' | '\u{1082}'..='\u{108d}' | '\u{108f}' | '\u{109a}'..='\u{109d}' |
        '\u{135d}'..='\u{135f}' | '\u{1712}'..='\u{1715}' | '\u{1732}'..='\u{1734}' |
        '\u{1752}'..='\u{1753}' | '\u{1772}'..='\u{1773}' | '\u{17b4}'..='\u{17d3}' |
        '\u{180b}'..='\u{180d}' | '\u{1885}'..='\u{1886}' | '\u{18a9}' | '\u{1920}'..='\u{193b}' |
        '\u{1a17}'..='\u{1a7f}' | '\u{1ab0}'..='\u{1ace}' | '\u{1b00}'..='\u{1b44}' |
        '\u{1b6b}'..='\u{1b73}' | '\u{1b80}'..='\u{1baa}' | '\u{1be6}'..='\u{1bf3}' |
        '\u{1c24}'..='\u{1c37}' | '\u{1cd0}'..='\u{1cf9}' | '\u{1dc0}'..='\u{1dff}' |
        '\u{203f}'..='\u{2040}' | '\u{2054}' | '\u{20d0}'..='\u{20f0}' | '\u{2cef}'..='\u{2cf1}' |
        '\u{2d7f}' | '\u{2de0}'..='\u{2dff}' | '\u{302a}'..='\u{302f}' | '\u{3099}'..='\u{309a}' |
        '\u{a66f}'..='\u{a672}' | '\u{a674}'..='\u{a67d}' | '\u{a69e}'..='\u{a69f}' |
        '\u{a6f0}'..='\u{a6f1}' | '\u{a802}' | '\u{a806}' | '\u{a80b}' | '\u{a823}'..='\u{a827}' |
        '\u{a880}'..='\u{a881}' | '\u{a8b4}'..='\u{a8c5}' | '\u{a8e0}'..='\u{a8f1}' |
        '\u{a8ff}' | '\u{a926}'..='\u{a92d}' | '\u{a947}'..='\u{a953}' | '\u{a980}'..='\u{a983}' |
        '\u{a9b3}'..='\u{a9c0}' | '\u{a9e5}' | '\u{aa29}'..='\u{aa36}' | '\u{aa43}' |
        '\u{aa4c}'..='\u{aa4d}' | '\u{aa7b}'..='\u{aa7d}' | '\u{aab0}' | '\u{aab2}'..='\u{aab4}' |
        '\u{aab7}'..='\u{aab8}' | '\u{aabe}'..='\u{aabf}' | '\u{aac1}' | '\u{aaeb}'..='\u{aaef}' |
        '\u{aaf5}'..='\u{aaf6}' | '\u{abe3}'..='\u{abea}' | '\u{abec}'..='\u{abed}' |
        '\u{fb1e}' | '\u{fe00}'..='\u{fe0f}' | '\u{fe20}'..='\u{fe2f}' | '\u{fe33}'..='\u{fe34}' |
        '\u{fe4d}'..='\u{fe4f}' | '\u{ff3f}' | '\u{101fd}' | '\u{102e0}' | '\u{10376}'..='\u{1037a}' |
        '\u{10a01}'..='\u{10a0f}' | '\u{10a38}'..='\u{10a3f}' | '\u{10ae5}'..='\u{10ae6}' |
        '\u{10d24}'..='\u{10d27}' | '\u{10eab}'..='\u{10eac}' | '\u{10efd}'..='\u{10eff}' |
        '\u{10f46}'..='\u{10f50}' | '\u{10f82}'..='\u{10f85}' | '\u{11000}'..='\u{11002}' |
        '\u{11038}'..='\u{11046}' | '\u{11070}'..='\u{11073}' | '\u{1107f}'..='\u{11082}' |
        '\u{110b0}'..='\u{110ba}' | '\u{11100}'..='\u{11102}' | '\u{11127}'..='\u{11134}' |
        '\u{11145}'..='\u{11146}' | '\u{11173}' | '\u{11180}'..='\u{11182}' | '\u{111b3}'..='\u{111c0}' |
        '\u{111c9}'..='\u{111cc}' | '\u{1122c}'..='\u{11237}' | '\u{1123e}' | '\u{112df}'..='\u{112ea}' |
        '\u{11300}'..='\u{11303}' | '\u{1133b}'..='\u{1133c}' | '\u{1133e}'..='\u{11344}' |
        '\u{11347}'..='\u{11348}' | '\u{1134b}'..='\u{1134d}' | '\u{11357}' | '\u{11362}'..='\u{11363}' |
        '\u{11435}'..='\u{11446}' | '\u{1145e}' | '\u{114b0}'..='\u{114c3}' | '\u{114c6}' |
        '\u{115af}'..='\u{115c0}' | '\u{115dc}'..='\u{115dd}' | '\u{11630}'..='\u{11640}' |
        '\u{116ab}'..='\u{116b7}' | '\u{1171d}'..='\u{1172b}' | '\u{1182c}'..='\u{1183a}' |
        '\u{11930}'..='\u{1193e}' | '\u{11940}' | '\u{11942}'..='\u{11943}' | '\u{119d1}'..='\u{119e4}' |
        '\u{11a01}'..='\u{11a0a}' | '\u{11a33}'..='\u{11a39}' | '\u{11a3b}'..='\u{11a3e}' |
        '\u{11a47}' | '\u{11a51}'..='\u{11a5b}' | '\u{11a8a}'..='\u{11a99}' | '\u{11c2f}'..='\u{11c36}' |
        '\u{11c38}'..='\u{11c3f}' | '\u{11c92}'..='\u{11ca7}' | '\u{11ca9}'..='\u{11cb6}' |
        '\u{11d31}'..='\u{11d47}' | '\u{11d8a}'..='\u{11d97}' | '\u{11ef3}'..='\u{11ef6}' |
        '\u{11f00}'..='\u{11f03}' | '\u{11f34}'..='\u{11f42}' | '\u{13430}'..='\u{13440}' |
        '\u{16af0}'..='\u{16af4}' | '\u{16b30}'..='\u{16b36}' | '\u{16f4f}' | '\u{16f51}'..='\u{16f87}' |
        '\u{16f8f}'..='\u{16f92}' | '\u{16fe4}' | '\u{16ff0}'..='\u{16ff1}' | '\u{1bc9d}'..='\u{1bc9e}' |
        '\u{1cf00}'..='\u{1cf46}' | '\u{1d165}'..='\u{1d169}' | '\u{1d16d}'..='\u{1d182}' |
        '\u{1d185}'..='\u{1d18b}' | '\u{1d1aa}'..='\u{1d1ad}' | '\u{1d242}'..='\u{1d244}' |
        '\u{1da00}'..='\u{1da36}' | '\u{1da3b}'..='\u{1da6c}' | '\u{1da75}' | '\u{1da84}' |
        '\u{1da9b}'..='\u{1daaf}' | '\u{1e000}'..='\u{1e02a}' | '\u{1e130}'..='\u{1e136}' |
        '\u{1e2ae}' | '\u{1e2ec}'..='\u{1e2ef}' | '\u{1e4ec}'..='\u{1e4ef}' | '\u{1e8d0}'..='\u{1e8d6}' |
        '\u{1e944}'..='\u{1e94a}' | '\u{e0100}'..='\u{e01ef}'
    )
}

fn boundary_matches(boundary: Boundary, text: &str, start: usize, end: usize) -> bool {
    let previous = previous_char(text, start);
    let next = next_char(text, end);
    match boundary {
        Boundary::None => true,
        Boundary::Email => {
            !previous.is_some_and(|c| is_word(c) || ".!#$%&'*+/=?^`{|}~@-".contains(c))
                && !next.is_some_and(|c| is_word(c) || matches!(c, '@' | '-'))
                && !(next == Some('.')
                    && next_char(text, end + 1)
                        .is_some_and(|c| is_word(c) || matches!(c, '.' | '-')))
        }
        Boundary::WordHyphen => {
            !previous.is_some_and(|c| is_word(c) || c == '-')
                && !next.is_some_and(|c| is_word(c) || c == '-')
        }
        Boundary::Cpf => {
            !previous.is_some_and(|c| is_word(c) || matches!(c, '.' | '-'))
                && !next.is_some_and(|c| is_word(c) || c == '-')
        }
        Boundary::Card => {
            !previous.is_some_and(|c| c.is_ascii_digit())
                && !next.is_some_and(|c| c.is_ascii_digit())
        }
        Boundary::Ip => {
            if text[start..end].contains(':') {
                boundary_matches(Boundary::Ipv6, text, start, end)
            } else {
                boundary_matches(Boundary::Ipv4, text, start, end)
            }
        }
        Boundary::Ipv6 => {
            !previous.is_some_and(|c| is_word(c) || matches!(c, ':' | '.' | '%'))
                && !next.is_some_and(|c| is_word(c) || matches!(c, ':' | '%'))
                && !(next == Some('.')
                    && next_char(text, end + 1).is_some_and(|c| is_word(c) || c == '.'))
        }
        Boundary::Ipv4 => {
            !previous.is_some_and(|c| c.is_ascii_digit() || c == '.')
                && !next.is_some_and(|c| c.is_ascii_digit() || c == '.')
        }
        Boundary::Address | Boundary::Date => !next.is_some_and(|c| {
            if matches!(boundary, Boundary::Date) {
                c.is_ascii_digit()
            } else {
                c.is_alphanumeric()
            }
        }),
        Boundary::LabelledIdentifier => !next.is_some_and(|c| is_word(c) || c == '-'),
        Boundary::Mac => {
            !previous.is_some_and(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '-'))
                && !next.is_some_and(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '-'))
        }
        Boundary::Aws => {
            !previous.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '+'))
                && !next.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '+'))
        }
        Boundary::Google => {
            !next.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        }
        Boundary::Jwt => {
            !previous.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
                && !next.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        }
        Boundary::AsciiAlnum => {
            !previous.is_some_and(|c| c.is_ascii_alphanumeric())
                && !next.is_some_and(|c| c.is_ascii_alphanumeric())
        }
        Boundary::Secret => !previous.is_some_and(|c| c.is_alphanumeric()),
    }
}

fn email(_text: &str, _start: usize, value: &str) -> f32 {
    let Some(at) = value.find('@') else {
        return 0.0;
    };
    let local = &value[..at];
    let domain = &value[at + 1..];
    if local.chars().count() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.chars().count() > 253
    {
        return 0.0;
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.chars().count() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || label.contains('_')
        {
            return 0.0;
        }
    }
    // IDNA validates Unicode labels and punycode without changing the evidence span.
    if idna::domain_to_ascii(domain).is_err() {
        return 0.0;
    }
    0.99
}

fn ssn_dashed(text: &str, start: usize, value: &str) -> f32 {
    ssn_confidence(text, start, value, 0.8, 0.35)
}

fn ssn_labelled(text: &str, start: usize, value: &str) -> f32 {
    ssn_confidence(text, start, value, 0.9, 0.5)
}

fn ssn_spaced(text: &str, start: usize, value: &str) -> f32 {
    if ssn_structure_valid(value) {
        ssn_confidence(text, start, value, 0.55, 0.0)
    } else {
        0.0
    }
}

fn ssn_confidence(text: &str, start: usize, value: &str, valid: f32, invalid: f32) -> f32 {
    let mut confidence = if ssn_structure_valid(value) {
        valid
    } else {
        invalid
    };
    let mut prefix = &text[..start];
    while prefix.ends_with(' ') {
        prefix = &prefix[..prefix.len() - 1];
    }
    if prefix.ends_with('#') {
        confidence *= 0.5;
    }
    confidence
}

pub(super) fn ssn_structure_valid(value: &str) -> bool {
    let mut digits = [0u8; 9];
    let mut count = 0;
    for byte in value.bytes().filter(|byte| byte.is_ascii_digit()) {
        if count == 9 {
            return false;
        }
        digits[count] = byte - b'0';
        count += 1;
    }
    if count != 9 {
        return false;
    }
    let area = u16::from(digits[0]) * 100 + u16::from(digits[1]) * 10 + u16::from(digits[2]);
    let group = digits[3] * 10 + digits[4];
    let serial = u16::from(digits[5]) * 1000
        + u16::from(digits[6]) * 100
        + u16::from(digits[7]) * 10
        + u16::from(digits[8]);
    if area == 0 || area == 666 || area >= 900 || group == 0 || serial == 0 {
        return false;
    }
    !(area == 78 && group == 5 && serial == 1120) && !(area == 219 && group == 9 && serial == 9999)
}

fn card(text: &str, start: usize, value: &str) -> f32 {
    if !luhn(value) {
        return 0.0;
    }
    let prefix_start = start.saturating_sub(24);
    let suffix_end = (start + value.len() + 24).min(text.len());
    if has_digit_group_before(&text[prefix_start..start])
        || has_digit_group_after(&text[start + value.len()..suffix_end])
    {
        return 0.0;
    }
    let mut digits = [0u8; 19];
    let mut count = 0;
    for byte in value.bytes().filter(|byte| byte.is_ascii_digit()) {
        if count == 19 {
            return 0.0;
        }
        digits[count] = byte - b'0';
        count += 1;
    }
    if count < 2 {
        return 0.0;
    }
    let p2 = u16::from(digits[0]) * 10 + u16::from(digits[1]);
    let p3 = if count >= 3 {
        p2 * 10 + u16::from(digits[2])
    } else {
        0
    };
    let p4 = if count >= 4 {
        p3 * 10 + u16::from(digits[3])
    } else {
        0
    };
    if digits[0] == 4 {
        return if matches!(count, 13 | 16 | 19) {
            0.9
        } else {
            0.0
        };
    }
    if (51..=55).contains(&p2) || (2221..=2720).contains(&p4) {
        return if count == 16 { 0.9 } else { 0.0 };
    }
    if matches!(p2, 34 | 37) {
        return if count == 15 { 0.9 } else { 0.0 };
    }
    if matches!(p2, 36 | 38 | 39) || (300..=305).contains(&p3) || p4 == 3095 {
        return if (14..=19).contains(&count) {
            0.85
        } else {
            0.0
        };
    }
    if (3528..=3589).contains(&p4) {
        return if (16..=19).contains(&count) {
            0.85
        } else {
            0.0
        };
    }
    if p4 == 6011 || (644..=649).contains(&p3) || matches!(p2, 65 | 62) {
        return if (16..=19).contains(&count) {
            0.85
        } else {
            0.0
        };
    }
    if matches!(p2, 50 | 56 | 57 | 58 | 63 | 67) {
        return if (12..=19).contains(&count) { 0.6 } else { 0.0 };
    }
    0.0
}

fn has_digit_group_before(text: &str) -> bool {
    let bytes = text.as_bytes();
    let Some(&separator) = bytes.last() else {
        return false;
    };
    if !matches!(separator, b' ' | b'-') {
        return false;
    }
    let digits = bytes[..bytes.len() - 1]
        .iter()
        .rev()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    digits >= 3
}

fn has_digit_group_after(text: &str) -> bool {
    let bytes = text.as_bytes();
    let Some(&separator) = bytes.first() else {
        return false;
    };
    if !matches!(separator, b' ' | b'-') {
        return false;
    }
    bytes[1..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count()
        >= 3
}

pub(super) fn luhn(text: &str) -> bool {
    if !text.is_ascii() {
        return luhn_chars(text);
    }
    let mut count = 0;
    let mut sum = 0u32;
    let mut first = None;
    let mut different = false;
    for byte in text.bytes().rev() {
        if matches!(byte, b' ' | b'-' | b'.') {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
        count += 1;
        if count > 19 {
            return false;
        }
        let mut digit = u32::from(byte - b'0');
        if let Some(first) = first {
            different |= digit != first;
        } else {
            first = Some(digit);
        }
        if count % 2 == 0 {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    count >= 8 && different && sum.is_multiple_of(10)
}

fn luhn_chars(text: &str) -> bool {
    let mut count = 0;
    let mut sum = 0u32;
    let mut first = None;
    let mut different = false;
    for c in text.chars().rev() {
        if matches!(c, ' ' | '-' | '.' | '\u{00a0}' | '\u{202f}') {
            continue;
        }
        if !c.is_ascii_digit() {
            return false;
        }
        count += 1;
        if count > 19 {
            return false;
        }
        let mut digit = c as u32 - '0' as u32;
        if let Some(first) = first {
            different |= digit != first;
        } else {
            first = Some(digit);
        }
        if count % 2 == 0 {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    count >= 8 && different && sum.is_multiple_of(10)
}

fn ip(text: &str, start: usize, value: &str) -> f32 {
    let without_scope = value.split_once('%').map_or(value, |(address, _)| address);
    let Ok(mut address) = without_scope.parse::<IpAddr>() else {
        return 0.0;
    };
    let mut prefix_end = start;
    let bytes = text.as_bytes();
    while prefix_end > 0 && matches!(bytes[prefix_end - 1], b' ' | b'\t') {
        prefix_end -= 1;
    }
    let word_end = prefix_end;
    while prefix_end > 0 && bytes[prefix_end - 1].is_ascii_alphabetic() {
        prefix_end -= 1;
    }
    let version_like = ["v", "ver", "version", "build", "release", "rev"]
        .iter()
        .any(|word| text[prefix_end..word_end].eq_ignore_ascii_case(word));

    match &mut address {
        IpAddr::V4(ipv4) => score_ipv4(ipv4.octets(), version_like),
        IpAddr::V6(ipv6) => {
            if let Some(mapped) = ipv6.to_ipv4_mapped() {
                return score_ipv4(mapped.octets(), version_like);
            }
            let octets = ipv6.octets();
            let segments = ipv6.segments();
            let link_local = segments[0] & 0xffc0 == 0xfe80;
            let site_local = segments[0] & 0xffc0 == 0xfec0;
            if ipv6.is_unspecified()
                || ipv6.is_loopback()
                || ipv6.is_multicast()
                || link_local
                || octets[..4] == [0x20, 0x01, 0x0d, 0xb8]
            {
                0.3
            } else if octets[0] & 0xfe == 0xfc || site_local {
                0.6
            } else {
                0.8
            }
        }
    }
}

fn score_ipv4(bytes: [u8; 4], version_like: bool) -> f32 {
    let bits = u32::from_be_bytes(bytes);
    let special = matches!(bytes[0], 0 | 127 | 224..=255)
        || (bytes[0] == 169 && bytes[1] == 254)
        || (bytes[0] == 192 && bytes[1] == 0 && matches!(bytes[2], 0 | 2))
        || (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
        || (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
        || (!bits & bits.wrapping_neg()) == 0;
    if special {
        return 0.3;
    }
    let private = bytes[0] == 10
        || (bytes[0] == 172 && (16..=31).contains(&bytes[1]))
        || (bytes[0] == 192 && bytes[1] == 168)
        || (bytes[0] == 100 && (64..=127).contains(&bytes[1]));
    if version_like {
        0.3
    } else if private {
        0.6
    } else {
        0.8
    }
}

fn labelled_identifier(_text: &str, _start: usize, value: &str) -> f32 {
    let Some(label_end) = value.find([':', '=', '#']) else {
        return 0.0;
    };
    let identifier = &value[label_end + 1..];
    let identifier = identifier.trim_start_matches([' ', '\t']);
    if !(5..=26).contains(&identifier.len())
        || !identifier.bytes().any(|byte| byte.is_ascii_digit())
    {
        return 0.0;
    }
    let bytes = identifier.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(byte, b' ' | b'\t') && !bytes.get(index + 1).is_some_and(u8::is_ascii_digit) {
            return 0.0;
        }
    }
    0.65
}

fn mac(_text: &str, _start: usize, value: &str) -> f32 {
    let bytes = value.as_bytes();
    if value.contains('.') {
        if bytes.iter().any(|byte| matches!(byte, b':' | b'-')) {
            return 0.0;
        }
    } else {
        let Some(separator) = bytes.iter().find(|byte| matches!(byte, b':' | b'-')) else {
            return 0.0;
        };
        if bytes
            .iter()
            .filter(|byte| matches!(byte, b':' | b'-'))
            .any(|byte| byte != separator)
        {
            return 0.0;
        }
    }
    let hex: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_hexdigit())
        .collect();
    if hex.len() != 12 {
        return 0.0;
    }
    if hex.iter().all(|byte| *byte == b'0') || hex.iter().all(|byte| matches!(byte, b'f' | b'F')) {
        return 0.3;
    }
    if hex.iter().any(u8::is_ascii_alphabetic) || value.contains(':') {
        0.7
    } else {
        0.4
    }
}

fn secret(_text: &str, _start: usize, value: &str) -> f32 {
    const PLACEHOLDERS: &[&str] = &[
        "null",
        "none",
        "true",
        "false",
        "changeme",
        "password",
        "redacted",
        "example",
        "secret",
        "required",
        "optional",
        "undefined",
        "<redacted>",
        "********",
    ];
    if value.len() < 8
        || PLACEHOLDERS
            .iter()
            .any(|placeholder| value.eq_ignore_ascii_case(placeholder))
        || value
            .chars()
            .all(|c| matches!(c, '*' | 'x' | 'X' | '•' | '#'))
        || value.starts_with(['$', '%', '{', '<', '@', '[', '('])
    {
        return 0.0;
    }
    let digit = value.bytes().any(|byte| byte.is_ascii_digit());
    let symbol = value.chars().any(|c| !c.is_alphanumeric());
    let mixed = value.chars().any(char::is_uppercase) && value.chars().any(char::is_lowercase);
    if !digit && !symbol && !(mixed && value.len() >= 12) {
        return 0.0;
    }
    if digit && symbol { 0.75 } else { 0.6 }
}

fn date_of_birth(_text: &str, _start: usize, value: &str) -> f32 {
    if let Some(captures) = DOB_NUMERIC_VALUE.captures_iter(value).last() {
        let (Some(first), Some(second), Some(third)) =
            (captures.get(1), captures.get(2), captures.get(3))
        else {
            return 0.0;
        };
        let (Ok(a), Ok(b), Ok(c)) = (
            first.as_str().parse::<i32>(),
            second.as_str().parse::<i32>(),
            third.as_str().parse::<i32>(),
        ) else {
            return 0.0;
        };
        let valid = if first.len() == 4 {
            national_ids::valid_date(a, b as u32, c as u32)
        } else {
            let year = expand_short_year(c);
            national_ids::valid_date(year, b as u32, a as u32)
                || national_ids::valid_date(year, a as u32, b as u32)
        };
        return if valid { 0.9 } else { 0.0 };
    }
    if let Some(captures) = DOB_DAY_MONTH_VALUE.captures_iter(value).last() {
        let (Some(day), Some(month), Some(year)) =
            (captures.get(1), captures.get(2), captures.get(3))
        else {
            return 0.0;
        };
        let (Ok(day), Ok(year), Some(month)) = (
            day.as_str().parse::<u32>(),
            year.as_str().parse::<i32>(),
            month_number(month.as_str()),
        ) else {
            return 0.0;
        };
        return if national_ids::valid_date(expand_short_year(year), month, day) {
            0.9
        } else {
            0.0
        };
    }
    if let Some(captures) = DOB_MONTH_DAY_VALUE.captures_iter(value).last() {
        let (Some(month), Some(day), Some(year)) =
            (captures.get(1), captures.get(2), captures.get(3))
        else {
            return 0.0;
        };
        let (Ok(day), Ok(year), Some(month)) = (
            day.as_str().parse::<u32>(),
            year.as_str().parse::<i32>(),
            month_number(month.as_str()),
        ) else {
            return 0.0;
        };
        return if national_ids::valid_date(expand_short_year(year), month, day) {
            0.9
        } else {
            0.0
        };
    }
    0.0
}

const fn expand_short_year(year: i32) -> i32 {
    if year >= 0 && year <= 99 {
        2000 + year
    } else {
        year
    }
}

fn month_number(month: &str) -> Option<u32> {
    let mut lower = [0u8; 9];
    if month.len() > lower.len() || !month.is_ascii() {
        return None;
    }
    for (target, source) in lower.iter_mut().zip(month.bytes()) {
        *target = source.to_ascii_lowercase();
    }
    let lower = std::str::from_utf8(&lower[..month.len()]).ok()?;
    match lower {
        "jan" | "january" => Some(1),
        "feb" | "february" => Some(2),
        "mar" | "march" => Some(3),
        "apr" | "april" => Some(4),
        "may" => Some(5),
        "jun" | "june" => Some(6),
        "jul" | "july" => Some(7),
        "aug" | "august" => Some(8),
        "sep" | "sept" | "september" => Some(9),
        "oct" | "october" => Some(10),
        "nov" | "november" => Some(11),
        "dec" | "december" => Some(12),
        _ => None,
    }
}

static IBAN_LENGTHS: LazyLock<HashMap<&'static str, usize>> = LazyLock::new(|| {
    const REGISTRY: &str = concat!(
        "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BI27 BR29 BY28 CH21 CR22 CY28 CZ24 ",
        "DE22 DJ27 DK18 DO28 EE20 EG29 ES24 FI18 FK18 FO18 FR27 GB22 GE22 GI23 GL18 GR27 GT28 HN28 HR21 HU28 ",
        "IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 LV21 LY25 MC27 MD24 ME22 MK19 MN20 ",
        "MR27 MT31 MU30 NI28 NL18 NO15 OM23 PK24 PL28 PS29 PT25 QA29 RO24 RS22 RU33 SA24 SC31 SD18 SE24 SI19 ",
        "SK24 SM27 SO23 ST25 SV28 TL23 TN24 TR26 UA29 VA22 VG24 XK20 YE30 ",
        "AX18 GF27 GP27 MQ27 RE27 PF27 TF27 YT27 NC27 BL27 MF27 PM27 WF27 IM22 JE22 GG22"
    );
    REGISTRY
        .split_whitespace()
        .filter_map(|entry| {
            let (country, length) = entry.split_at(2);
            Some((country, length.parse().ok()?))
        })
        .collect()
});

fn iban_candidate_length(text: &str, start: usize) -> Option<usize> {
    if previous_char(text, start).is_some_and(is_word) {
        return None;
    }
    let prefix = text.get(start..start + 4)?;
    let country = &prefix[..2];
    let mut upper = [0u8; 2];
    for (target, source) in upper.iter_mut().zip(country.bytes()) {
        *target = source.to_ascii_uppercase();
    }
    let upper = std::str::from_utf8(&upper).ok()?;
    let expected = *IBAN_LENGTHS.get(upper)?;
    let bytes = text.as_bytes();
    let mut end = start + 4;
    for _ in 4..expected {
        if matches!(bytes.get(end), Some(b' ' | b'\t')) {
            end += 1;
        }
        if !bytes.get(end).is_some_and(u8::is_ascii_alphanumeric) {
            return None;
        }
        end += 1;
    }
    if next_char(text, end).is_some_and(is_word) {
        return None;
    }
    Some(end - start)
}

pub(super) fn iban(text: &str) -> bool {
    let mut value = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, ' ' | '\t' | '\u{00a0}' | '\u{202f}') {
            continue;
        }
        if !c.is_ascii_alphanumeric() {
            return false;
        }
        value.push(c.to_ascii_uppercase());
    }
    if !(15..=34).contains(&value.len())
        || IBAN_LENGTHS
            .get(&value[..2])
            .is_none_or(|length| *length != value.len())
    {
        return false;
    }
    if !value.as_bytes()[2..4].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let mut remainder = 0u32;
    for byte in value.as_bytes()[4..].iter().chain(&value.as_bytes()[..4]) {
        if byte.is_ascii_digit() {
            remainder = (remainder * 10 + u32::from(byte - b'0')) % 97;
        } else if byte.is_ascii_uppercase() {
            remainder = (remainder * 100 + u32::from(byte - b'A') + 10) % 97;
        } else {
            return false;
        }
    }
    remainder == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(text: &str, kind: EntityType) -> Vec<&str> {
        PatternDetector::default()
            .detect(text)
            .into_iter()
            .filter(|span| span.entity_type == kind)
            .map(|span| &text[span.start..span.start + span.length])
            .collect()
    }

    fn single(text: &str, kind: EntityType) -> EntitySpan {
        let matches: Vec<_> = PatternDetector::default()
            .detect(text)
            .into_iter()
            .filter(|span| span.entity_type == kind)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected one {kind:?} in {text:?}, got {matches:?}"
        );
        matches.into_iter().next().unwrap_or_else(|| unreachable!())
    }

    fn assert_value(span: &EntitySpan, text: &str, expected: &str) {
        assert_eq!(&text[span.start..span.start + span.length], expected);
        assert_eq!(span.start, text.find(expected).unwrap_or(usize::MAX));
    }

    #[test]
    fn ip_forms_have_one_exact_span() {
        for (text, expected) in [
            (
                "IP: 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            ),
            ("IP: 2001:db8::1.", "2001:db8::1"),
            ("https://[2001:DB8::1]:443/path", "2001:DB8::1"),
            ("IP: ::1", "::1"),
            ("IP: ::", "::"),
            ("IP: ::ffff:192.0.2.128", "::ffff:192.0.2.128"),
            ("IP: fe80::1%12", "fe80::1%12"),
            ("Subnet: 2001:db8::/32", "2001:db8::"),
            ("IP: 192.0.2.1", "192.0.2.1"),
            (
                "host abcd:efab:abcd:efab:abcd:efab:abcd:efab",
                "abcd:efab:abcd:efab:abcd:efab:abcd:efab",
            ),
        ] {
            assert_value(&single(text, EntityType::IpAddress), text, expected);
        }
    }

    #[test]
    fn invalid_ip_tokens_do_not_produce_fragments() {
        for text in [
            "2001:db8:::1",
            "2001:db8::1::2",
            "2001:db8:1:2:3:4:5:6:7",
            "2001:db8::12345",
            "2001:db8::xyz",
            "fe80::1%invalid",
            "::ffff:999.0.2.1",
            "12:34:56",
            "999.999.999.999",
        ] {
            assert!(values(text, EntityType::IpAddress).is_empty(), "{text}");
        }
        assert!(values("aa:bb:cc:dd:ee:ff", EntityType::IpAddress).is_empty());
    }

    #[test]
    fn ip_confidence_reflects_reserved_private_public_and_version_context() {
        for (ip, expected) in [
            ("127.0.0.1", 0.3),
            ("0.0.0.0", 0.3),
            ("255.255.255.0", 0.3),
            ("192.0.2.1", 0.3),
            ("192.168.1.100", 0.6),
            ("10.20.30.40", 0.6),
            ("203.0.113.9", 0.3),
            ("8.8.8.8", 0.8),
            ("2001:db8::1", 0.3),
            ("fe80::1", 0.3),
            ("2a00:1450:4001:80b::200e", 0.8),
        ] {
            assert_eq!(
                single(&format!("host {ip} seen"), EntityType::IpAddress).confidence,
                expected,
                "{ip}"
            );
        }
        assert!(
            single("Version 1.2.3.4 released", EntityType::IpAddress).confidence
                < single("Host 1.2.3.4 released", EntityType::IpAddress).confidence
        );
    }

    #[test]
    fn email_formats_and_assignment_metadata_keep_exact_values() {
        for (text, expected) in [
            (
                "Contact <o'neill+work@example.co.uk>.",
                "o'neill+work@example.co.uk",
            ),
            (
                "Email: alice@example.com. Next sentence.",
                "alice@example.com",
            ),
            ("Email: josé@exämple.org", "josé@exämple.org"),
            ("email=alice@example.com", "alice@example.com"),
            (
                "keyword=Comment, value=metadata.only@example.net",
                "metadata.only@example.net",
            ),
            ("Contact a=b@example.com", "a=b@example.com"),
            ("alice@example.xn--p1ai", "alice@example.xn--p1ai"),
            ("alice@example.XN--P1AI", "alice@example.XN--P1AI"),
        ] {
            assert_value(&single(text, EntityType::Email), text, expected);
        }
    }

    #[test]
    fn malformed_emails_packages_and_oversized_components_are_rejected() {
        for text in [
            "a..b@example.com",
            ".alice@example.com",
            "alice.@example.com",
            "alice@example.com_bad",
            "alice@example.com-bad-",
            "alice@example.com..invalid",
            "alice@-example.com",
            "Dependency lodash@4.17.21 and @types/node@18.0.0 installed",
            "user@host.1",
        ] {
            assert!(values(text, EntityType::Email).is_empty(), "{text}");
        }
        for text in [
            format!("{}@example.com", "a".repeat(65)),
            format!("a@{}.com", "b".repeat(64)),
        ] {
            assert!(values(&text, EntityType::Email).is_empty());
        }
    }

    #[test]
    fn long_non_email_tokens_do_not_hide_later_matches() {
        let text = format!("{} end@example.com", "!".repeat(100_000));
        assert_value(&single(&text, EntityType::Email), &text, "end@example.com");
    }

    #[test]
    fn contextual_and_formatted_ssns_keep_candidates_but_score_structure() {
        for (text, expected) in [
            ("SSN: 123456789", "123456789"),
            ("ssn = 000000000", "000000000"),
            ("SSN # 666123456", "666123456"),
            ("Social Security number: 900123456", "900123456"),
            ("social_security_number=123456789", "123456789"),
            ("Social Security No. 123456789", "123456789"),
            ("unissued: 000-00-0000", "000-00-0000"),
            ("synthetic: 666-12-3456", "666-12-3456"),
            ("synthetic: 900-12-3456", "900-12-3456"),
        ] {
            assert_value(
                &single(text, EntityType::SocialSecurityNumber),
                text,
                expected,
            );
        }
        assert!(PatternDetector::ssn_structure_valid("123-45-6789"));
        for invalid in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "123-00-3456",
            "123-45-0000",
            "078-05-1120",
        ] {
            assert!(!PatternDetector::ssn_structure_valid(invalid));
        }
        let valid = single("SSN 123-45-6789 on file", EntityType::SocialSecurityNumber).confidence;
        let flagged =
            single("SSN 666-12-3456 on file", EntityType::SocialSecurityNumber).confidence;
        let ticket = single(
            "Ticket #123-45-6789 escalated",
            EntityType::SocialSecurityNumber,
        )
        .confidence;
        assert!(valid > flagged && flagged > 0.0 && ticket < valid);
        assert_eq!(
            values("SSN 123 45 6789 on file", EntityType::SocialSecurityNumber),
            ["123 45 6789"]
        );
        assert!(values("Score 000 00 0000 today", EntityType::SocialSecurityNumber).is_empty());
    }

    #[test]
    fn undashed_ssns_require_a_label_and_exactly_nine_digits() {
        for text in [
            "Order: 123456789",
            "SSN: 1234567890",
            "SSN: 123456789A",
            "SSN:\r\nOrder 123456789",
            "SSN: 12345678",
        ] {
            assert!(
                values(text, EntityType::SocialSecurityNumber).is_empty(),
                "{text}"
            );
        }
    }

    #[test]
    fn labelled_names_preserve_offsets_without_crossing_cells_or_lines() {
        for (text, expected) in [
            (
                "prefix\r\nFull name: Maria Hernandez\r\nnext",
                "Maria Hernandez",
            ),
            (
                "[Table] FULL  NAME :\tAnne-Marie O’Neill   | other",
                "Anne-Marie O’Neill",
            ),
            ("Full name: 李", "李"),
            ("Attn: Sarah Connor", "Sarah Connor"),
            ("Patient name: Wei Zhang | ward 3", "Wei Zhang"),
            ("Employee: Maria Hernandez (HR)", "Maria Hernandez"),
            ("NAME: MARIA HERNANDEZ | DOB: 1984-03-11", "MARIA HERNANDEZ"),
        ] {
            assert_value(&single(text, EntityType::Person), text, expected);
        }
        for text in [
            "Full name:\r\nMaria Hernandez",
            "Full name: | Maria Hernandez",
            "File name: Report Final",
            "Customer: pending",
            "Product name: Acme Widget",
        ] {
            assert!(values(text, EntityType::Person).is_empty(), "{text}");
        }
    }

    #[test]
    fn international_and_domestic_phone_forms_use_configured_regions() {
        for (text, expected) in [
            ("Call (415) 555-0142 today", "(415) 555-0142"),
            ("Call 020 7946 0958 (London)", "020 7946 0958"),
            ("Call +49 30 1234567 (Berlin)", "+49 30 1234567"),
            ("Call +33 1 23 45 67 89 (Paris)", "+33 1 23 45 67 89"),
            ("Call +91 98765 43210 (India)", "+91 98765 43210"),
            ("Call +81 3-1234-5678 (Tokyo)", "+81 3-1234-5678"),
            ("Tel: +1.212.555.0100 ext. 123", "+1.212.555.0100 ext. 123"),
            ("Tel: 1-800-555-0199", "1-800-555-0199"),
            ("+44 (0)20 7946 0958", "+44 (0)20 7946 0958"),
        ] {
            assert_value(&single(text, EntityType::Phone), text, expected);
        }
        let german = PatternDetector::new(["de, nope, US"]);
        assert_eq!(german.phone_regions(), &["DE".to_owned(), "US".to_owned()]);
        assert!(values("Call 030 1234567 from Berlin", EntityType::Phone).is_empty());
        assert_eq!(
            german
                .detect("Call 030 1234567 from Berlin")
                .iter()
                .filter(|span| span.entity_type == EntityType::Phone)
                .count(),
            1
        );
    }

    #[test]
    fn invalid_number_shapes_are_not_phones_and_bare_numbers_score_lower() {
        for text in [
            "Invoice 2024-09-1234 paid",
            "Event at epoch 1725551234 by user 42",
            "Serial 1234567890",
            "Case 1112223333",
            "Phone +1 000 000 0000 is invalid",
            "GET /api/items/4155550142 200",
            "Version 2026.09.10 build 20240911",
            "CPF 123.456.789-09",
            "CPF 123.456.789-00",
            "Record 987.654.321-00",
            "IMEI number: 14155550142",
        ] {
            assert!(values(text, EntityType::Phone).is_empty(), "{text}");
        }
        assert!(
            single("Order 4155550142 shipped", EntityType::Phone).confidence
                < single("Call 415-555-0142", EntityType::Phone).confidence
        );
        assert!(values("NHS number: 943 476 5919", EntityType::Phone).is_empty());
        assert!(!values("NHS helpline: 943 476 5919", EntityType::Phone).is_empty());
        assert_value(
            &single("Call 415.555.0142", EntityType::Phone),
            "Call 415.555.0142",
            "415.555.0142",
        );
    }

    #[test]
    fn luhn_and_issuer_ranges_validate_cards_without_windows_of_longer_numbers() {
        for (text, valid) in [
            ("4111111111111111", true),
            ("4111 1111 1111 1111", true),
            ("4111-1111-1111-1111", true),
            ("4111\u{00a0}1111\u{00a0}1111\u{00a0}1111", true),
            ("4111\u{202f}1111\u{202f}1111\u{202f}1111", true),
            ("4111x1111x1111x1111", false),
            ("4111\n1111\n1111\n1111", false),
            ("0000000000000000", false),
            ("4111111111111112", false),
        ] {
            assert_eq!(PatternDetector::luhn(text), valid, "{text}");
        }
        for (text, expected) in [
            ("Visa 4111 1111 1111 1111", "4111 1111 1111 1111"),
            ("MC 5500 0000 0000 0004", "5500 0000 0000 0004"),
            ("Amex 3400 0000 0000 009", "3400 0000 0000 009"),
            ("Discover 6011 0000 0000 0004", "6011 0000 0000 0004"),
            ("JCB 3530 1113 3330 0000", "3530 1113 3330 0000"),
            ("Card 4111111111111111 exp 12/26", "4111111111111111"),
        ] {
            assert_value(&single(text, EntityType::PaymentCard), text, expected);
        }
        for text in [
            "IMEI 356938035643809 registered",
            "Visa 4111 1111 1111 1111 1112",
            "Prefix 1234 4111 1111 1111 1111 done",
            "ref 1234567890123 (13 digits)",
        ] {
            assert!(values(text, EntityType::PaymentCard).is_empty(), "{text}");
        }
        let text = "Card: 4111\u{00a0}1111\u{00a0}1111\u{00a0}1111.";
        assert_value(
            &single(text, EntityType::PaymentCard),
            text,
            "4111\u{00a0}1111\u{00a0}1111\u{00a0}1111",
        );
    }

    #[test]
    fn dates_of_birth_cover_written_months_and_reject_impossible_dates() {
        for (text, expected) in [
            ("Born on 11-Mar-1984", "Born on 11-Mar-1984"),
            ("D.O.B. 11/03/84", "D.O.B. 11/03/84"),
            ("Birthday: 11th March 1984", "Birthday: 11th March 1984"),
            (
                "Date of Birth: March 11, 1984",
                "Date of Birth: March 11, 1984",
            ),
            (
                "Date of birth 1984-03-11T00:00:00",
                "Date of birth 1984-03-11",
            ),
            ("DOB: 2024-02-29", "DOB: 2024-02-29"),
        ] {
            assert_value(&single(text, EntityType::DateOfBirth), text, expected);
        }
        for text in [
            "DOB: 2023-02-29",
            "DOB: 2024-04-31",
            "Birthday: 31 February 2020",
            "Born on 32-Mar-1984",
        ] {
            assert!(values(text, EntityType::DateOfBirth).is_empty(), "{text}");
        }
        let text = "DOB: 2023-02-30 contact alice@example.com";
        assert!(!values(text, EntityType::Email).is_empty());
        assert!(values(text, EntityType::DateOfBirth).is_empty());
    }

    #[test]
    fn street_addresses_cover_numbered_units_boxes_and_european_forms() {
        for (text, expected) in [
            ("350 5th Avenue, New York, NY 10118", "350 5th Avenue"),
            ("123 E 42nd Street", "123 E 42nd Street"),
            ("P.O. Box 123, Springfield", "P.O. Box 123"),
            ("221B Baker Street", "221B Baker Street"),
            ("1 Infinite Loop, Cupertino", "1 Infinite Loop"),
            ("100 Main St. Apt 4B", "100 Main St. Apt 4B"),
            (
                "1600 Pennsylvania Avenue NW, Washington",
                "1600 Pennsylvania Avenue NW",
            ),
            ("12 Rue de la Paix, Paris", "12 Rue de la Paix"),
            ("Bahnhofstraße 12, Berlin", "Bahnhofstraße 12"),
            ("Via Roma 15, Milano", "Via Roma 15"),
            ("POB 123", "POB 123"),
        ] {
            assert_value(&single(text, EntityType::StreetAddress), text, expected);
        }
        for text in ["It was a 2 hour drive to the coast", "sent via email 2024"] {
            assert!(values(text, EntityType::StreetAddress).is_empty(), "{text}");
        }
    }

    #[test]
    fn uk_ni_and_country_specific_ibans_have_bounded_spans() {
        assert_value(
            &single("NI: AB123456C", EntityType::UkNationalInsurance),
            "NI: AB123456C",
            "AB123456C",
        );
        for (text, expected) in [
            (
                "Transfer GB82 WEST 1234 5698 7654 32 REF approved",
                "GB82 WEST 1234 5698 7654 32",
            ),
            (
                "Transfer gb82 west 1234 5698 7654 32 today",
                "gb82 west 1234 5698 7654 32",
            ),
            (
                "DE89 3704 0044 0532 0130 00 TOTAL",
                "DE89 3704 0044 0532 0130 00",
            ),
            (
                "IBAN: GB82\u{00a0}WEST\u{202f}1234 5698 7654 32",
                "GB82\u{00a0}WEST\u{202f}1234 5698 7654 32",
            ),
        ] {
            assert_value(&single(text, EntityType::Iban), text, expected);
        }
        for text in [
            "ZZ82370400440532013000",
            "GB82WEST123456987654321",
            "GB82 WEST 1234 5698 7654 33",
            "GBXXWEST12345698765432",
        ] {
            assert!(!PatternDetector::iban(text));
            assert!(values(text, EntityType::Iban).is_empty(), "{text}");
        }
        let qatar = (2..=97)
            .map(|number| format!("QA{number:02}{}", "A".repeat(25)))
            .find(|value| iban(value))
            .unwrap_or_default();
        assert!(!qatar.is_empty());
        assert_eq!(values(&qatar, EntityType::Iban), [qatar.as_str()]);
    }

    #[test]
    fn common_identifier_labels_stop_at_the_value() {
        for (text, expected) in [
            (
                "Passport number: AB1234567 expires tomorrow",
                "Passport number: AB1234567",
            ),
            (
                "Passport No. = AB1234567 | other",
                "Passport No. = AB1234567",
            ),
            (
                "Driver’s license number: D123-456-789, CA",
                "Driver’s license number: D123-456-789",
            ),
            (
                "drivers license: D1234567\r\nNext row",
                "drivers license: D1234567",
            ),
            (
                "Driving licence no.: AB 1234567 |",
                "Driving licence no.: AB 1234567",
            ),
            ("Passport: AB1234567", "Passport: AB1234567"),
            ("Account number: 123456789 |", "Account number: 123456789"),
            ("Tax ID: 12-3456789", "Tax ID: 12-3456789"),
            ("patient number: 123456", "patient number: 123456"),
            ("member number: 123456", "member number: 123456"),
            (
                "medical record number: 123456",
                "medical record number: 123456",
            ),
        ] {
            assert_value(
                &single(text, EntityType::LabelledIdentifier),
                text,
                expected,
            );
        }
        for text in [
            "Passport number: pending",
            "Driver's license: expired",
            "Passport number:\r\nOrder 1234567",
            "Passport number: AB123456789012345678901234567890",
        ] {
            assert!(
                values(text, EntityType::LabelledIdentifier).is_empty(),
                "{text}"
            );
        }
    }

    #[test]
    fn mac_addresses_require_consistent_separators() {
        for (text, expected, confidence) in [
            ("MAC 00:1A:2B:3C:4D:5E seen", "00:1A:2B:3C:4D:5E", 0.7),
            ("MAC 00-1a-2b-3c-4d-5e seen", "00-1a-2b-3c-4d-5e", 0.7),
            ("MAC 001a.2b3c.4d5e seen", "001a.2b3c.4d5e", 0.7),
            ("MAC ff:ff:ff:ff:ff:ff seen", "ff:ff:ff:ff:ff:ff", 0.3),
        ] {
            let span = single(text, EntityType::MacAddress);
            assert_value(&span, text, expected);
            assert_eq!(span.confidence, confidence);
        }
        for text in ["2024-09-10-12-30-45", "00:1A:2B:3C:4D", "00:1A-2B:3C-4D:5E"] {
            assert!(values(text, EntityType::MacAddress).is_empty(), "{text}");
        }
    }

    #[test]
    fn credentials_report_their_specific_method_and_exact_value() {
        for (text, expected, kind) in [
            (
                "AWS key AKIAIOSFODNN7EXAMPLE leaked",
                "AKIAIOSFODNN7EXAMPLE",
                "AWS access key",
            ),
            (
                "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456",
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456",
                "GitHub token",
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
                "private key",
            ),
            (
                "slack xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
                "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
                "Slack token",
            ),
            (
                "google AIzaSyA1234567890abcdefghijklmnopqrstuv",
                "AIzaSyA1234567890abcdefghijklmnopqrstuv",
                "Google API key",
            ),
            (
                "jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "JSON Web Token",
            ),
            (
                "db_password = Tr0ub4dor&3",
                "Tr0ub4dor&3",
                "labelled secret",
            ),
            (
                "api_key: \"sk-abc123def456ghi789\"",
                "sk-abc123def456ghi789",
                "labelled secret",
            ),
            (
                "stripe sk_live_ABCDEFGHIJKLMNOP",
                "sk_live_ABCDEFGHIJKLMNOP",
                "Stripe key",
            ),
        ] {
            let span = single(text, EntityType::Credential);
            assert_value(&span, text, expected);
            assert_eq!(span.method, format!("Pattern ({kind})"));
        }
    }

    #[test]
    fn secrets_reject_placeholders_and_trim_trailing_sentence_punctuation() {
        for text in [
            "password: ********",
            "password = ${DB_PASSWORD}",
            "Reset your password: required.",
            "secret: changeme",
            "api_key = <your key here>",
        ] {
            assert!(values(text, EntityType::Credential).is_empty(), "{text}");
        }
        let span = single(
            "password = Tr0ub4dor&3. Next sentence",
            EntityType::Credential,
        );
        assert_value(
            &span,
            "password = Tr0ub4dor&3. Next sentence",
            "Tr0ub4dor&3",
        );
        assert_eq!(span.confidence, 0.75);
        assert!(values("password = short.", EntityType::Credential).is_empty());
    }

    #[test]
    fn wallets_require_base58_segwit_or_eip55_checksums() {
        for (text, kind) in [
            ("btc 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "Bitcoin address"),
            ("btc 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "Bitcoin address"),
            (
                "btc bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                "Bitcoin address",
            ),
            (
                "btc bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
                "Bitcoin address",
            ),
            (
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                "Bitcoin address",
            ),
            ("BC1SW50QGDZ25J", "Bitcoin address"),
            (
                "eth 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                "Ethereum address",
            ),
            (
                "eth 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                "Ethereum address",
            ),
        ] {
            let span = single(text, EntityType::CryptoWallet);
            assert_eq!(span.method, format!("Pattern ({kind})"));
            assert_eq!(span.confidence, 0.95);
        }
        for text in [
            "btc 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3",
            "btc bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr",
            "eth 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD",
            "commit 3a19fe9404a4469d91aa3d551558a97f68872f67",
        ] {
            assert!(values(text, EntityType::CryptoWallet).is_empty(), "{text}");
        }
    }

    #[test]
    fn national_identifiers_verify_check_digits_and_report_country_methods() {
        for (text, expected, country) in [
            ("CPF 123.456.789-09", "123.456.789-09", "Brazil CPF"),
            ("Aadhaar 2234 5678 9018", "2234 5678 9018", "India Aadhaar"),
            ("NHS number: 943 476 5919", "943 476 5919", "UK NHS number"),
            ("SIN 130 692 544", "130 692 544", "Canada SIN"),
            ("DNI 12345678Z", "12345678Z", "Spain DNI/NIE"),
            ("NIE X1234567L", "X1234567L", "Spain DNI/NIE"),
            (
                "CF RSSMRA85T10A562S",
                "RSSMRA85T10A562S",
                "Italy codice fiscale",
            ),
            ("PESEL 44051401359", "44051401359", "Poland PESEL"),
            (
                "NIR 2 69 05 49 588 157 80",
                "2 69 05 49 588 157 80",
                "France NIR",
            ),
            (
                "NIR 1 84 03 75 123 456 90",
                "1 84 03 75 123 456 90",
                "France NIR",
            ),
            (
                "personnummer 811218-9876",
                "811218-9876",
                "Sweden personnummer",
            ),
            ("BSN: 111222333", "111222333", "Netherlands BSN"),
            ("TFN 123 456 782", "123 456 782", "Australia TFN"),
            (
                "ID number 8001015009087",
                "8001015009087",
                "South Africa ID",
            ),
            ("RRN 900101-1234568", "900101-1234568", "Korea RRN"),
            (
                "ID 11010519491231002X",
                "11010519491231002X",
                "China resident ID",
            ),
        ] {
            let span = single(text, EntityType::NationalId);
            assert_value(&span, text, expected);
            assert_eq!(span.method, format!("Pattern ({country})"));
        }
        for text in [
            "CPF 123.456.789-00",
            "Aadhaar 2234 5678 9013",
            "NHS number: 943 476 5918",
            "SIN 130 692 545",
            "SIN 046 454 286",
            "DNI 12345678A",
            "CF RSSMRA85T10A562T",
            "PESEL 44051401358",
            "PESEL 44991401359",
            "NIR 2 69 05 49 588 157 81",
            "BSN: 111222334",
            "TFN 123 456 789",
            "RRN 900101-1234569",
            "RRN 901301-1234568",
            "ID 11010519491231002Y",
            "phone 415 555 0142",
            "NHS 000 000 0000",
            "TFN 000 000 000",
        ] {
            assert!(values(text, EntityType::NationalId).is_empty(), "{text}");
        }
        for (labelled, bare) in [
            ("SIN 130 692 544", "ref 130 692 544"),
            ("PESEL 44051401359", "order 44051401359"),
            ("Aadhaar 2234 5678 9018", "code 2234 5678 9018"),
            ("ID number 8001015009087", "batch 8001015009087"),
        ] {
            assert!(
                single(labelled, EntityType::NationalId).confidence
                    > single(bare, EntityType::NationalId).confidence
            );
        }
    }

    #[test]
    fn normalization_retains_original_utf8_evidence_and_marks_only_changed_spans() {
        for (text, expected, kind) in [
            (
                "Ｅｍａｉｌ： ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ",
                "ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ",
                EntityType::Email,
            ),
            (
                "Send to ali\u{200b}ce@example.com now",
                "ali\u{200b}ce@example.com",
                EntityType::Email,
            ),
            (
                "Contact ali\u{2060}ce@exam\u{00ad}ple.com",
                "ali\u{2060}ce@exam\u{00ad}ple.com",
                EntityType::Email,
            ),
            (
                "Contact josé@exa\u{200b}mple.com",
                "josé@exa\u{200b}mple.com",
                EntityType::Email,
            ),
            (
                "SSN: ١٢٣٤٥٦٧٨٩",
                "١٢٣٤٥٦٧٨٩",
                EntityType::SocialSecurityNumber,
            ),
            (
                "SSN: １２３－４５－６７８９",
                "１２３－４５－６７８９",
                EntityType::SocialSecurityNumber,
            ),
            (
                "SSN: 123\u{2011}45\u{2011}6789",
                "123\u{2011}45\u{2011}6789",
                EntityType::SocialSecurityNumber,
            ),
            (
                "Card: ４１１１ １１１１ １１１１ １１１１",
                "４１１１ １１１１ １１１１ １１１１",
                EntityType::PaymentCard,
            ),
            (
                "emoji 😀 alice\u{200b}@example.com",
                "alice\u{200b}@example.com",
                EntityType::Email,
            ),
        ] {
            let span = single(text, kind);
            assert_value(&span, text, expected);
            assert!(
                span.method.ends_with(" (Unicode normalized)"),
                "{}",
                span.method
            );
        }
        let text = "Note\u{200b}: alice@example.com";
        let span = single(text, EntityType::Email);
        assert_eq!(span.method, "Pattern");
        assert_value(&span, text, "alice@example.com");
        let text = "josé@example.com\u{200b}";
        let span = single(text, EntityType::Email);
        assert_eq!(span.method, "Pattern");
        assert_value(&span, text, "josé@example.com");
        for text in [
            "\u{200b}\u{2060}\u{00ad}",
            "Order: １２３４５６７８９",
            "Card: ４１１１ １１１１ １１１１ １１１２",
        ] {
            assert!(PatternDetector::default().detect(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn overlap_resolution_handles_duplicates_nested_spans_and_non_monotonic_ends() {
        let candidates = [
            EntitySpan::new(EntityType::LabelledIdentifier, 0, 100, 0.8, "Pattern"),
            EntitySpan::new(EntityType::LabelledIdentifier, 10, 5, 0.9, "Pattern"),
            EntitySpan::new(EntityType::Phone, 20, 10, 0.5, "Pattern"),
        ];
        let resolved = PatternDetector::resolve(candidates);
        assert!(
            !resolved
                .iter()
                .any(|span| span.entity_type == EntityType::Phone)
        );
        assert_eq!(resolved.len(), 2);

        let duplicates = [
            EntitySpan::new(EntityType::Email, 0, 17, 0.6, "weaker"),
            EntitySpan::new(EntityType::Email, 0, 17, 0.99, "stronger"),
        ];
        let resolved = PatternDetector::resolve(duplicates);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].method, "stronger");

        let spans = PatternDetector::default().detect("Account number: 4155550142");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::LabelledIdentifier);
        assert_eq!(
            single("ssn = 123-45-6789", EntityType::SocialSecurityNumber).confidence,
            0.9
        );
    }

    #[test]
    fn broad_negative_controls_do_not_produce_unrelated_pattern_findings() {
        for text in [
            "4111 1111 1111 1112",
            "0000000000000000",
            "999.999.999.999",
            "The release is version 12.34.56 and contains 125 files.",
            "Nothing to report.",
        ] {
            assert!(PatternDetector::default().detect(text).is_empty(), "{text}");
        }
    }
}
