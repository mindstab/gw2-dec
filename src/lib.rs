use byte_slice_cast::*;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::rc4::Rc4;
use crypto::symmetriccipher::Decryptor;

fn hash_sha1_5_rounds(buffer: &[u8]) -> [u32; 5] {
    let mut block = [0u32; 5];
    for i in 0..5 {
        block[i] = u32::from_le_bytes([
            buffer[(0 + i * std::mem::size_of::<u32>()) % buffer.len()],
            buffer[(1 + i * std::mem::size_of::<u32>()) % buffer.len()],
            buffer[(2 + i * std::mem::size_of::<u32>()) % buffer.len()],
            buffer[(3 + i * std::mem::size_of::<u32>()) % buffer.len()],
        ]);
    }

    let digest: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    let mut a = digest[0];
    let mut b = digest[1];
    let mut c = digest[2];
    let mut d = digest[3];
    let mut e = digest[4];

    macro_rules! round {
        ($b:expr, $v:expr, $w:expr, $x:expr, $y:expr, $z:expr) => {{
            $z = $z
                .wrapping_add(($w & ($x ^ $y)) ^ $y)
                .wrapping_add($b)
                .wrapping_add(0x5a827999)
                .wrapping_add(u32::rotate_left($v, 5));
            $w = u32::rotate_left($w, 30);
        }};
    }
    round!(block[0], a, b, c, d, e);
    round!(block[1], e, a, b, c, d);
    round!(block[2], d, e, a, b, c);
    round!(block[3], c, d, e, a, b);
    round!(block[4], b, c, d, e, a);

    block[0] = a.wrapping_add(block[0]);
    block[1] = b.wrapping_add(block[1]);
    block[2] = c.wrapping_add(block[2]);
    block[3] = d.wrapping_add(block[3]);
    block[4] = e.wrapping_add(block[4]);

    block
}

pub fn decrypt_content(buffer: &[u8], encryption_key: u64) -> Vec<u8> {
    assert_ne!(encryption_key, 0, "no encryption key provided");

    let mut rc4 = Rc4::new(hash_sha1_5_rounds(&encryption_key.to_le_bytes()).as_byte_slice());
    let mut read_buffer = RefReadBuffer::new(&buffer);
    let mut buffer = vec![0; buffer.len()];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    rc4.decrypt(&mut read_buffer, &mut write_buffer, true)
        .expect("rc4 key should be valid");

    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        assert_eq!(
            hash_sha1_5_rounds(&[0]),
            [1767594110, 3454876413, 2237877336, 391182560, 3891078700]
        );
        assert_eq!(
            hash_sha1_5_rounds(&[189, 18, 232, 109, 99, 1, 0, 0]),
            [1633013001, 3595917109, 3076530891, 1183944831, 1901018521]
        );
        assert_eq!(
            hash_sha1_5_rounds(&[2, 144, 10, 222, 12, 22, 0, 0]),
            [2436012694, 818488442, 2650843801, 128291966, 1031428655]
        );
        assert_eq!(
            hash_sha1_5_rounds(&[96, 252, 192, 246, 50, 2, 0, 0]),
            [136872302, 1275449793, 986773855, 1297669790, 3697172900]
        );
        assert_eq!(
            hash_sha1_5_rounds(&[84, 39, 26, 241, 52, 3, 0, 0]),
            [4293378276, 3693701906, 3446860578, 3760338816, 3578648405]
        );
    }

    #[test]
    fn test_decrypt() {
        assert_eq!(
            decrypt_content(
                &[
                    0x69, 0x9c, 0xfe, 0xa2, 0x82, 0x2f, 0xb1, 0xbb, 0x65, 0x25, 0x0b, 0x06, 0xd9,
                    0x1b
                ],
                1526557315773
            ),
            [32, 133, 16, 184, 32, 110, 94, 10, 162, 16, 137, 64, 58, 23]
        );
        assert_eq!(
            decrypt_content(&[0xfd, 0xb1, 0x49, 0x21, 0x0e, 0xe7, 0xba], 24244520652802),
            [32, 230, 226, 200, 80, 8, 21]
        );
        assert_eq!(
            decrypt_content(
                &[0xce, 0x92, 0x68, 0x37, 0x16, 0x7c, 0xe1, 0xb5, 0x7b, 0x81, 0x93, 0x93],
                2417911463008
            ),
            [169, 197, 111, 19, 29, 38, 132, 27, 208, 80, 241, 3]
        );
        assert_eq!(
            decrypt_content(
                &[0xca, 0x53, 0x24, 0xeb, 0x5d, 0xd6, 0x60, 0x28, 0x32, 0xc3, 0x68, 0x5d, 0x2a],
                731060601321
            ),
            [32, 164, 98, 3, 74, 36, 24, 11, 98, 131, 184, 72, 0]
        );
    }
}
