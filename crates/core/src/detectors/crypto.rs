use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// Validate a Base58Check Bitcoin address. The accepted versions are mainnet/testnet
/// P2PKH and P2SH, matching the legacy detector.
pub(super) fn bitcoin(value: &str) -> f32 {
    let Ok(decoded) = bs58::decode(value).into_vec() else {
        return 0.0;
    };
    if decoded.len() != 25 || !matches!(decoded[0], 0x00 | 0x05 | 0x6f | 0xc4) {
        return 0.0;
    }
    let first = Sha256::digest(&decoded[..21]);
    let second = Sha256::digest(first);
    if second[..4] == decoded[21..] {
        0.95
    } else {
        0.0
    }
}

/// Decode a SegWit address with the bech32 crate's BIP-173/BIP-350 implementation.
/// This checks checksum variant, witness version, converted-bit padding and program length.
pub(super) fn bech32(value: &str) -> f32 {
    if value.len() > 90 {
        return 0.0;
    }
    let Ok((hrp, _, _)) = bech32::segwit::decode(value) else {
        return 0.0;
    };
    if hrp == bech32::hrp::BC || hrp == bech32::hrp::TB {
        0.95
    } else {
        0.0
    }
}

/// Validate an Ethereum address, including EIP-55 when its mixed case carries a checksum.
pub(super) fn ethereum(value: &str) -> f32 {
    let Some(hex) = value.strip_prefix("0x") else {
        return 0.0;
    };
    if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return 0.0;
    }
    let has_upper = hex.bytes().any(|byte| byte.is_ascii_uppercase());
    let has_lower = hex.bytes().any(|byte| byte.is_ascii_lowercase());
    if !has_upper || !has_lower {
        return if hex.bytes().all(|byte| byte == b'0') {
            0.0
        } else {
            0.6
        };
    }

    let lowercase = hex.to_ascii_lowercase();
    let hash = keccak256(lowercase.as_bytes());
    for (index, byte) in hex.bytes().enumerate() {
        if !byte.is_ascii_alphabetic() {
            continue;
        }
        let nibble = if index % 2 == 0 {
            hash[index / 2] >> 4
        } else {
            hash[index / 2] & 0x0f
        };
        if byte.is_ascii_uppercase() != (nibble >= 8) {
            return 0.0;
        }
    }
    0.95
}

/// Keccak-256 uses the original 0x01 padding, not SHA3-256's 0x06 padding.
pub(super) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0; 32];
    hasher.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58check_accepts_published_addresses_and_rejects_changes() {
        for value in [
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        ] {
            assert_eq!(bitcoin(value), 0.95);
        }
        assert_eq!(bitcoin("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"), 0.0);
        assert_eq!(bitcoin("not-a-wallet"), 0.0);
    }

    #[test]
    fn segwit_requires_the_right_checksum_and_witness_program() {
        for value in [
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "BC1SW50QGDZ25J",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
        ] {
            assert_eq!(bech32(value), 0.95, "{value}");
        }
        for value in [
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7k8e76x7",
            "bc1gmk9yu",
            "ltc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        ] {
            assert_eq!(bech32(value), 0.0, "{value}");
        }
    }

    #[test]
    fn keccak_and_eip55_match_reference_vectors() {
        assert_eq!(
            keccak256(b""),
            [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70,
            ]
        );
        let abc: Vec<String> = keccak256(b"abc")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            abc.concat(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(ethereum("0x71C7656EC7ab88b098defB751B7401B5f6d8976F"), 0.95);
        assert_eq!(ethereum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"), 0.95);
        assert_eq!(ethereum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"), 0.0);
        assert_eq!(ethereum("0x0000000000000000000000000000000000000000"), 0.0);
        assert_eq!(ethereum("0xde709f2102306220921060314715629080e2fb77"), 0.6);
    }
}
