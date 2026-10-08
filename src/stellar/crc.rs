//! CRC-16/XMODEM as used by Stellar StrKey.
//!
//! SEP-23 specifies the polynomial x^16 + x^12 + x^5 + 1. The maintained
//! implementations (stellar-core, stellar-go, js-stellar-base, and
//! `stellar-strkey`) use the XMODEM parameters: init `0x0000`, no reflection,
//! xorout `0x0000`. The 16-bit value is appended little-endian, low byte first.
//! `"123456789"` is the standard check value `0x31C3`.

/// CRC-16/XMODEM of `data`.
pub(crate) fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            if crc & 0x8000 == 0 {
                crc <<= 1;
            } else {
                crc = (crc << 1) ^ 0x1021;
            }
        }
    }
    crc
}

/// Two checksum bytes, low byte first.
pub(crate) fn checksum(data: &[u8]) -> [u8; 2] {
    let crc = crc16_xmodem(data);
    [crc as u8, (crc >> 8) as u8]
}

pub(crate) fn checksum_matches(left: [u8; 2], right: [u8; 2]) -> bool {
    let mut diff = 0u8;
    diff |= left[0] ^ right[0];
    diff |= left[1] ^ right[1];
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{checksum, crc16_xmodem};

    #[test]
    fn xmodem_check_value_is_little_endian() {
        assert_eq!(crc16_xmodem(b"123456789"), 0x31c3);
        assert_eq!(checksum(b"123456789"), [0xc3, 0x31]);
    }
}
