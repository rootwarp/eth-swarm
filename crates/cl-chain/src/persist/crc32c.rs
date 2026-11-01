//! CRC32C (Castagnoli, reflected polynomial `0x82F63B78`), as iSCSI (RFC 3720) and ext4 use
//! it: the checksum of every `import.log` frame. Table-driven, one byte at a time; the log is
//! small, so no hardware path.

/// The 256-entry table of the reflected polynomial, built at compile time.
const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// CRC32C of `data`.
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |crc, &byte| {
        TABLE[usize::from((crc as u8) ^ byte)] ^ (crc >> 8)
    })
}

#[cfg(test)]
mod tests {
    use super::crc32c;

    /// RFC 3720 (iSCSI) section B.4, and the CRC catalogue's check value.
    #[test]
    fn rfc_3720_vectors() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(&[0; 32]), 0x8a91_36aa);
        assert_eq!(crc32c(&[0xff; 32]), 0x62a8_ab43);
        let up: Vec<u8> = (0..32).collect();
        assert_eq!(crc32c(&up), 0x46dd_794e);
        let down: Vec<u8> = (0..32).rev().collect();
        assert_eq!(crc32c(&down), 0x113f_db5c);
        assert_eq!(crc32c(b""), 0);
    }
}
