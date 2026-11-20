//! Just enough Annex B parsing to classify an encoder's output.

/// Type (`nal_unit_type`) of the first coded-slice NAL unit (types 1 to 5) in an Annex B
/// byte stream, skipping SPS, PPS, SEI and other non-picture units. 5 means an IDR picture.
pub fn first_slice_nal_type(data: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 3 < data.len() {
        // Start code: 00 00 01 (a 4-byte start code just has one more leading zero).
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            let nal_type = data[i + 3] & 0x1f;
            if (1..=5).contains(&nal_type) {
                return Some(nal_type);
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    None
}

/// True when the stream starts a new coded video sequence with an IDR picture.
pub fn starts_with_idr(data: &[u8]) -> bool {
    first_slice_nal_type(data) == Some(5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_first_slice() {
        // SPS (7), PPS (8), SEI (6), IDR slice (5).
        let idr = [
            0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 3, 0, 0, 1, 0x06, 9, 0, 0, 1, 0x65, 7,
        ];
        assert_eq!(first_slice_nal_type(&idr), Some(5));
        assert!(starts_with_idr(&idr));
        let p = [0, 0, 0, 1, 0x41, 1, 2, 3];
        assert_eq!(first_slice_nal_type(&p), Some(1));
        assert!(!starts_with_idr(&p));
        assert_eq!(first_slice_nal_type(&[0, 0, 1, 0x67, 1]), None);
        assert_eq!(first_slice_nal_type(&[]), None);
        assert_eq!(first_slice_nal_type(&[0, 0, 1]), None);
    }
}
