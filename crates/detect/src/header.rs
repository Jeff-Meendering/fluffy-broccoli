//! Reading column headers: which element a column holds, and about whom.

use rollcall_model::ElementKind;

/// What a column contributes to a person record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Element(ElementKind),
    /// Name parts are joined into one name by the linker.
    FirstName,
    MiddleName,
    LastName,
    /// Second address line, appended to the first.
    AddressLine2,
}

/// A header's meaning: the role, and the related person it describes if not the row's
/// main subject (`Spouse SSN` is the spouse's number, not the employee's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMeaning {
    pub relation: Option<String>,
    pub role: Role,
}

/// Lower-cases a header and reduces punctuation and naming styles to single spaces, so
/// `First_Name`, `firstName` and `FIRST NAME` all read `first name`.
#[must_use]
pub fn normalize_header(raw: &str) -> String {
    let mut spaced = String::with_capacity(raw.len() + 8);
    let mut previous_lower = false;
    for character in raw.chars() {
        if character.is_uppercase() && previous_lower {
            spaced.push(' ');
        }
        previous_lower = character.is_lowercase();
        match character {
            '#' => spaced.push_str(" number "),
            '\'' | '\u{2019}' => {}
            _ if character.is_alphanumeric() => spaced.extend(character.to_lowercase()),
            _ => spaced.push(' '),
        }
    }
    spaced
        .split_whitespace()
        .map(|word| match word {
            "no" | "num" | "nbr" | "nr" => "number",
            "addr" => "address",
            "tel" => "telephone",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Words that start a header about someone other than the row's main subject.
const RELATIONS: [&str; 22] = [
    "emergency contact",
    "next of kin",
    "co applicant",
    "co borrower",
    "spouse",
    "partner",
    "dependent",
    "child",
    "beneficiary",
    "guardian",
    "parent",
    "mother",
    "father",
    "emergency",
    "manager",
    "supervisor",
    "physician",
    "doctor",
    "provider",
    "agent",
    "joint",
    "secondary",
];

/// Interprets a header cell, or returns `None` when it names nothing recognised.
#[must_use]
pub fn classify_header(raw: &str) -> Option<HeaderMeaning> {
    let header = normalize_header(raw);
    if header.is_empty() || header.len() > 60 {
        return None;
    }
    if let Some(role) = exact_role(&header) {
        return Some(HeaderMeaning {
            relation: None,
            role,
        });
    }
    for relation in RELATIONS {
        let Some(rest) = header.strip_prefix(relation) else {
            continue;
        };
        if !rest.is_empty() && !rest.starts_with(' ') {
            continue;
        }
        // "dependent 2 name": the number belongs to the relation.
        let mut words = rest.split_whitespace().peekable();
        let mut relation = relation.to_owned();
        if let Some(number) = words
            .peek()
            .filter(|word| word.bytes().all(|byte| byte.is_ascii_digit()))
        {
            relation = format!("{relation} {number}");
            words.next();
        }
        let rest = words.collect::<Vec<_>>().join(" ");
        let role = if rest.is_empty() {
            Role::Element(ElementKind::Name)
        } else {
            exact_role(&rest).or_else(|| suffix_role(&rest))?
        };
        return Some(HeaderMeaning {
            relation: Some(relation),
            role,
        });
    }
    suffix_role(&header).map(|role| HeaderMeaning {
        relation: None,
        role,
    })
}

/// True for headers that name a person only loosely (`Customer`, `Member`), where the
/// column might as easily hold an account number. The schema checks their content.
#[must_use]
pub fn is_loose_name_header(raw: &str) -> bool {
    matches!(
        normalize_header(raw).as_str(),
        "employee"
            | "patient"
            | "customer"
            | "member"
            | "client"
            | "student"
            | "insured"
            | "subscriber"
            | "applicant"
            | "resident"
            | "tenant"
            | "contact"
            | "recipient"
            | "payee"
            | "cardholder"
            | "card holder"
            | "account holder"
    )
}

/// Words in an `... name` header that show it does not name a person.
const NOT_A_PERSON: [&str; 31] = [
    "user",
    "file",
    "company",
    "business",
    "product",
    "bank",
    "school",
    "employer",
    "domain",
    "host",
    "group",
    "plan",
    "department",
    "dept",
    "project",
    "item",
    "job",
    "role",
    "team",
    "org",
    "organization",
    "organisation",
    "vendor",
    "facility",
    "branch",
    "city",
    "state",
    "country",
    "street",
    "login",
    "display",
];

fn exact_role(header: &str) -> Option<Role> {
    use ElementKind as Kind;
    let role = match header {
        "first name" | "firstname" | "fname" | "first" | "given name" | "givenname"
        | "forename" | "name first" => Role::FirstName,
        "last name" | "lastname" | "lname" | "last" | "surname" | "family name" | "familyname"
        | "name last" => Role::LastName,
        "middle name" | "middlename" | "middle" | "middle initial" | "mi" | "mname" => {
            Role::MiddleName
        }
        "name" | "full name" | "fullname" | "legal name" | "employee" | "patient" | "customer"
        | "member" | "client" | "student" | "insured" | "subscriber" | "applicant" | "resident"
        | "tenant" | "contact" | "recipient" | "payee" | "cardholder" | "card holder"
        | "account holder" => Role::Element(Kind::Name),
        "ssn"
        | "ss number"
        | "ssn number"
        | "social"
        | "social security"
        | "social security number"
        | "soc sec"
        | "soc sec number"
        | "ss"
        | "tin"
        | "tax id"
        | "taxid"
        | "taxpayer id"
        | "tax id number"
        | "taxpayer id number"
        | "ssn tin"
        | "tin ssn"
        | "itin"
        | "ssn itin" => Role::Element(Kind::Ssn),
        "dob" | "date of birth" | "dateofbirth" | "birth date" | "birthdate" | "birthday"
        | "d o b" | "born" => Role::Element(Kind::DateOfBirth),
        "email" | "e mail" | "email address" | "e mail address" | "emailaddress" => {
            Role::Element(Kind::Email)
        }
        "phone" | "phone number" | "telephone" | "telephone number" | "mobile"
        | "mobile number" | "cell" | "cell number" | "cellphone" | "contact number"
        | "phonenumber" => Role::Element(Kind::Phone),
        "address"
        | "street"
        | "street address"
        | "address1"
        | "address 1"
        | "address line 1"
        | "address line1"
        | "street 1"
        | "mailing address"
        | "home address"
        | "residential address"
        | "billing address"
        | "shipping address" => Role::Element(Kind::Address),
        "address2" | "address 2" | "address line 2" | "address line2" | "street 2" | "apt"
        | "apartment" | "unit" | "suite" => Role::AddressLine2,
        "city" | "town" | "city town" | "municipality" => Role::Element(Kind::City),
        "state" | "st" | "province" | "state province" | "province state" | "state code" => {
            Role::Element(Kind::State)
        }
        "zip" | "zip code" | "zipcode" | "postal code" | "postalcode" | "postcode"
        | "post code" | "postal" | "zip postal code" => Role::Element(Kind::PostalCode),
        "country" | "country code" | "nation" => Role::Element(Kind::Country),
        "card number"
        | "cardnumber"
        | "credit card"
        | "credit card number"
        | "cc"
        | "cc number"
        | "ccn"
        | "pan"
        | "card"
        | "debit card"
        | "debit card number"
        | "payment card"
        | "payment card number" => Role::Element(Kind::PaymentCard),
        "account number"
        | "accountnumber"
        | "bank account"
        | "bank account number"
        | "acct number"
        | "bank acct"
        | "bank acct number"
        | "checking account"
        | "savings account"
        | "deposit account"
        | "iban"
        | "dda" => Role::Element(Kind::BankAccount),
        "routing number"
        | "routingnumber"
        | "routing"
        | "aba"
        | "aba number"
        | "rtn"
        | "bank routing"
        | "bank routing number"
        | "routing transit number"
        | "aba routing number" => Role::Element(Kind::RoutingNumber),
        "drivers license"
        | "driver license"
        | "drivers licence"
        | "driver licence"
        | "drivers license number"
        | "driver license number"
        | "drivers licence number"
        | "driver licence number"
        | "driving licence"
        | "driving license"
        | "driving licence number"
        | "dl"
        | "dl number"
        | "dln"
        | "state id"
        | "state id number" => Role::Element(Kind::DriversLicence),
        "passport" | "passport number" => Role::Element(Kind::Passport),
        "mrn"
        | "medical record number"
        | "medical record"
        | "med rec number"
        | "patient id"
        | "patient number"
        | "chart number" => Role::Element(Kind::MedicalRecordNumber),
        "member id"
        | "member number"
        | "insurance id"
        | "insurance number"
        | "insurance member id"
        | "health insurance id"
        | "policy number"
        | "policy id"
        | "subscriber id"
        | "subscriber number"
        | "medicare number"
        | "medicare id"
        | "medicaid number"
        | "medicaid id"
        | "health plan id"
        | "hicn"
        | "mbi" => Role::Element(Kind::HealthInsuranceId),
        _ => return None,
    };
    Some(role)
}

/// Headers recognised by their last words: `Work Email`, `Home Phone`, `Patient Name`.
fn suffix_role(header: &str) -> Option<Role> {
    let words: Vec<&str> = header.split(' ').collect();
    let ends_with = |suffix: &[&str]| words.len() > suffix.len() && words.ends_with(suffix);
    if ends_with(&["email"]) || ends_with(&["email", "address"]) || ends_with(&["e", "mail"]) {
        return Some(Role::Element(ElementKind::Email));
    }
    if (ends_with(&["phone"]) || ends_with(&["phone", "number"]) || ends_with(&["telephone"]))
        && !words.contains(&"fax")
    {
        return Some(Role::Element(ElementKind::Phone));
    }
    if ends_with(&["name"]) && !words.iter().any(|word| NOT_A_PERSON.contains(word)) {
        return Some(Role::Element(ElementKind::Name));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(raw: &str) -> Option<Role> {
        classify_header(raw)
            .filter(|meaning| meaning.relation.is_none())
            .map(|meaning| meaning.role)
    }

    #[test]
    fn naming_styles_reduce_to_the_same_header() {
        for raw in [
            "First Name",
            "first_name",
            "firstName",
            "FIRST-NAME",
            " First  Name: ",
        ] {
            assert_eq!(normalize_header(raw), "first name", "{raw}");
        }
        assert_eq!(normalize_header("SSN #"), "ssn number");
        assert_eq!(
            normalize_header("Driver's License No."),
            "drivers license number"
        );
        assert_eq!(normalize_header("DOB"), "dob");
        assert_eq!(normalize_header("ZIPCode"), "zipcode");
    }

    #[test]
    fn recognises_common_headers() {
        use ElementKind as Kind;
        let expected = [
            ("SSN #", Kind::Ssn),
            ("Social Security Number", Kind::Ssn),
            ("Tax ID", Kind::Ssn),
            ("Date of Birth", Kind::DateOfBirth),
            ("E-mail", Kind::Email),
            ("Work Email", Kind::Email),
            ("Home Phone", Kind::Phone),
            ("Mobile", Kind::Phone),
            ("Mailing Address", Kind::Address),
            ("Province/State", Kind::State),
            ("Zip", Kind::PostalCode),
            ("Card Number", Kind::PaymentCard),
            ("Account Number", Kind::BankAccount),
            ("Routing No", Kind::RoutingNumber),
            ("Driver's License No.", Kind::DriversLicence),
            ("Passport #", Kind::Passport),
            ("MRN", Kind::MedicalRecordNumber),
            ("Member ID", Kind::HealthInsuranceId),
            ("Employee Name", Kind::Name),
            ("Full Name", Kind::Name),
        ];
        for (raw, kind) in expected {
            assert_eq!(role(raw), Some(Role::Element(kind)), "{raw}");
        }
        assert_eq!(role("First Name"), Some(Role::FirstName));
        assert_eq!(role("Surname"), Some(Role::LastName));
        assert_eq!(role("MI"), Some(Role::MiddleName));
        assert_eq!(role("Address Line 2"), Some(Role::AddressLine2));
    }

    #[test]
    fn leaves_non_personal_headers_alone() {
        for raw in [
            "Username",
            "User Name",
            "File Name",
            "Company Name",
            "Bank Name",
            "Fax Phone",
            "SKU",
            "Qty",
            "Unit Price",
            "Description",
            "Employee ID",
            "Parent Company",
            "",
        ] {
            assert_eq!(classify_header(raw), None, "{raw}");
        }
    }

    #[test]
    fn attributes_related_people_to_their_own_record() {
        let meaning = |raw| classify_header(raw).map(|found| (found.relation, found.role));
        assert_eq!(
            meaning("Spouse SSN"),
            Some((Some("spouse".to_owned()), Role::Element(ElementKind::Ssn)))
        );
        assert_eq!(
            meaning("Dependent 2 Date of Birth"),
            Some((
                Some("dependent 2".to_owned()),
                Role::Element(ElementKind::DateOfBirth)
            ))
        );
        assert_eq!(
            meaning("Emergency Contact"),
            Some((
                Some("emergency contact".to_owned()),
                Role::Element(ElementKind::Name)
            ))
        );
        assert_eq!(
            meaning("Emergency Contact Phone"),
            Some((
                Some("emergency contact".to_owned()),
                Role::Element(ElementKind::Phone)
            ))
        );
        assert_eq!(
            meaning("Manager"),
            Some((Some("manager".to_owned()), Role::Element(ElementKind::Name)))
        );
        assert_eq!(meaning("Partnership Type"), None);
    }
}
