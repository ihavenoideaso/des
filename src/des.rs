use crate::structs::*;

#[derive(Debug)]
pub struct DES {
    ip: [u8; 64],
    inv_ip: [usize; 64],
    e: [usize; 48],
    p: [usize; 32],
    shift: [u32; 16],
    pc_1: [usize; 56],
    pc_2: [usize; 48],
    sbox: [[[u8; 16]; 4]; 8]
}

impl DES {
    pub fn new() -> Self {
        Self {
            ip: IP,
            inv_ip: INV_IP,
            e: EXPANSION_TABLE,
            p: PERMUTATION_P,
            shift: SHIFTS,
            pc_1: PC_1,
            pc_2: PC_2,
            sbox: S_BOXES,
        }
    }

    pub fn encrypt(self, plaintext: [u8; 8], key: [u8; 8], n: u32) -> [u8; 8] {
        let mut text = Self::ascii_to_bits(plaintext);
        text = Self::permutation(text);
        let key_b = Self::ascii_to_bits(key);
        let ks_b = Self::key_schedule(key_b);

        let mut l = text[0..32].to_vec();
        let mut r = text[32..64].to_vec();
        for i in 0..n as usize {
            let old_l = l.clone();
            let old_r = r.clone();

            let res = Self::feistel(&old_r, &ks_b[i]);

            l = old_r;
            r = old_l
                .iter()
                .zip(res.iter())
                .map(|(a, b)| *a ^ *b)
                .collect();
        }
        let mut out = [false; 64];
        out[0..32].copy_from_slice(&r);
        out[32..64].copy_from_slice(&l);
        let mut res = [false; 64];
        for i in 0..64 as usize {
            res[i] = out[INV_IP[i]];
        }
        Self::bits_to_ascii(res)
    }

    fn do_e(x: &[bool]) -> [bool; 48] {
        let mut output = [false; 48];
        for i in 0..48 {
            output[i] = x[EXPANSION_TABLE[i]];
        }
        output
    }

    fn do_p(x: &[bool]) -> [bool; 32] {
        let mut output = [false; 32];
        for i in 0..32 {
            output[i] = x[PERMUTATION_P[i]];
        }
        output
    }

    fn feistel(x: &[bool], key: &[bool]) -> [bool; 32] {
        let mut e = Self::do_e(x);
        for i in 0..48 {
            e[i] ^= key[i];
        }
        let mut output = [false; 32];
        let mut counter = 0;
        for i in 0..8 {
            let v = &e[i * 6..i * 6 + 6];

            let row = (v[0] as usize) << 1 | (v[5] as usize);

            let col = (v[1] as usize) << 3
                    | (v[2] as usize) << 2
                    | (v[3] as usize) << 1
                    | (v[4] as usize);
            
            let u: u8 = S_BOXES[i][row][col];
            let bits: Vec<bool> = Self::sbox_to_bits(u);
            output[counter..counter+4].copy_from_slice(&bits);
            counter += 4;
        }
        Self::do_p(&output)
    }

    fn sbox_to_bits(n: u8) -> Vec<bool> {
        (0..4)
            .rev()
            .map(|i| ((n >> i) & 1) == 1)
            .collect()
    }

    fn do_pc_1(key: [bool; 64]) -> [bool; 56] {
        let mut output = [false; 56];
        for i in 0..PC_1.len() {
            output[i] = key[PC_1[i] as usize];
        }
        output
    }

    fn do_pc_2(keys: [[bool; 56]; 16]) -> [[bool; 48]; 16] {
        let mut output = [[false; 48]; 16];
        for i in 0..16 {
            for j in 0..PC_2.len() {
                output[i][j] = keys[i][PC_2[j] as usize];
            }
        }

        output
    }

    fn do_shift(L: &[bool], R: &[bool], shift: u32) -> ([bool; 28], [bool; 28]) {
        let mut Ls = [false; 28];
        let mut Rs = [false; 28];
        for i in 0..28 {
            Ls[i] = L[(i + shift as usize) % 28];
            Rs[i] = R[(i + shift as usize) % 28];
        }

        (Ls, Rs)
    }

    fn key_schedule(key: [bool; 64]) -> [[bool; 48]; 16] {
        let after_pc_1 = Self::do_pc_1(key);

        let mut L = after_pc_1[0..28].to_vec();
        let mut R = after_pc_1[28..56].to_vec();

        let mut ks_b = [[false; 56]; 16];
        for i in 0..16 {
            let (l, r) = Self::do_shift(&L, &R, SHIFTS[i]);
            L.copy_from_slice(&l);
            R.copy_from_slice(&r);
            ks_b[i][0..28].copy_from_slice(&L);
            ks_b[i][28..56].copy_from_slice(&R);
        }
        Self::do_pc_2(ks_b)
    }

    fn bit_to_byte(bits: &[bool]) -> u8 {
        let mut byte = 0u8;
        let mut index = 7;
        for i in bits.iter() {
            if *i {
                byte |= 1 << index;
            } else {
                byte |= 0 << index;
            }
            index -= 1;
        }
        byte
    }

    fn bits_to_ascii(bits: [bool; 64]) -> [u8; 8] {
        let mut result = [0u8; 8];
        for i in 0..8 {
            result[i] = Self::bit_to_byte(&bits[i*8..(i*8 + 8)]);
        }
        result
    }

    fn ascii_to_bits(plaintext: [u8; 8]) -> [bool; 64] {
        let mut result: [bool; 64] = [false; 64];
        for i in 0..64 {
            result[i] = ((plaintext[i / 8] >> (7 - (i % 8))) & 1) == 1;
        }

        result
    }

    fn permutation(inpt: [bool; 64]) -> [bool; 64] {
        let mut result: [bool; 64] = [false; 64];
        for i in 0..64 {
            result[i] = inpt[IP[i] as usize];
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_to_byte() {
        let input: [bool; 8] = [false, true, false, false, true, true, true, false];
        let result = DES::bit_to_byte(&input);
        let expect = 78;

        assert_eq!(result, expect);
    }

    #[test]
    fn test_ascii_to_bits() {
        let input: [u8; 8] = [0, 78, 0, 0, 0, 0, 0, 1];
        let res = DES::ascii_to_bits(input);
        let expect = [
            false, false, false, false, false, false, false, false,
            false, true, false, false, true, true, true, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, true,
        ];

        assert_eq!(res, expect);
    }

    #[test]
    fn test_bits_to_ascii() {
        let input = [
            false, false, false, false, false, false, false, false,
            false, true, false, false, true, true, true, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, true,
        ];
        let res = DES::bits_to_ascii(input);
        let expect: [u8; 8] = [0, 78, 0, 0, 0, 0, 0, 1];

        assert_eq!(res, expect);
    }
    #[test]
    fn test_permutation() {
        let input = [
            true, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            true, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, true,
        ];

        let res = DES::permutation(input);

        let expected = [
            false, false, false, false, false, false, true, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, true, false, false, false, false, false, true,
        ];

        assert_eq!(res, expected);
    }

    #[test]
    fn test_ks() {
        let key = [
            false, false, false, true, false, false, true, true,
            false, false, true, true, false, true, false, false,
            false, true, false, true, false, true, true, true,
            false, true, true, true, true, false, false, true,
            true, false, false, true, true, false, true, true,
            true, false, true, true, true, true, false, false,
            true, true, false, true, true, true, true, true,
            true, true, true, true, false, false, false, true,
        ];

        let res = DES::key_schedule(key);

        let expected = [
            // K1
            [
                false, false, false, true, true, false,
                true, true, false, false, false, false,
                false, false, true, false, true, true,
                true, false, true, true, true, true,
                true, true, true, true, true, true,
                false, false, false, true, true, true,
                false, false, false, false, false, true,
                true, true, false, false, true, false,
            ],
            // K2
            [
                false, true, true, true, true, false,
                false, true, true, false, true, false,
                true, true, true, false, true, true,
                false, true, true, false, false, true,
                true, true, false, true, true, false,
                true, true, true, true, false, false,
                true, false, false, true, true, true,
                true, false, false, true, false, true,
            ],
            // K3
            [
                false, true, false, true, false, true,
                false, true, true, true, true, true,
                true, true, false, false, true, false,
                false, false, true, false, true, false,
                false, true, false, false, false, false,
                true, false, true, true, false, false,
                true, true, true, true, true, false,
                false, true, true, false, false, true,
            ],
            // K4
            [
                false, true, true, true, false, false,
                true, false, true, false, true, false,
                true, true, false, true, true, true,
                false, true, false, true, true, false,
                true, true, false, true, true, false,
                true, true, false, false, true, true,
                false, true, false, true, false, false,
                false, true, true, true, false, true,
            ],
            // K5
            [
                false, true, true, true, true, true,
                false, false, true, true, true, false,
                true, true, false, false, false, false,
                false, false, false, true, true, true,
                true, true, true, false, true, false,
                true, true, false, true, false, true,
                false, false, true, true, true, false,
                true, false, true, false, false, false,
            ],
            // K6
            [
                false, true, true, false, false, false,
                true, true, true, false, true, false,
                false, true, false, true, false, false,
                true, true, true, true, true, false,
                false, true, false, true, false, false,
                false, false, false, true, true, true,
                true, false, true, true, false, false,
                true, false, true, true, true, true,
            ],
            // K7
            [
                true, true, true, false, true, true,
                false, false, true, false, false, false,
                false, true, false, false, true, false,
                true, true, false, true, true, true,
                true, true, true, true, false, true,
                true, false, false, false, false, true,
                true, false, false, false, true, false,
                true, true, true, true, false, false,
            ],
            // K8
            [
                true, true, true, true, false, true,
                true, true, true, false, false, false,
                true, false, true, false, false, false,
                true, true, true, false, true, false,
                true, true, false, false, false, false,
                false, true, false, false, true, true,
                true, false, true, true, true, true,
                true, true, true, false, true, true,
            ],
            // K9
            [
                true, true, true, false, false, false,
                false, false, true, true, false, true,
                true, false, true, true, true, true,
                true, false, true, false, true, true,
                true, true, true, false, true, true,
                false, true, true, true, true, false,
                false, true, true, true, true, false,
                false, false, false, false, false, true,
            ],
            // K10
            [
                true, false, true, true, false, false,
                false, true, true, true, true, true,
                false, false, true, true, false, true,
                false, false, false, true, true, true,
                true, false, true, true, true, false,
                true, false, false, true, false, false,
                false, true, true, false, false, true,
                false, false, true, true, true, true,
            ],
            // K11
            [
                false, false, true, false, false, false,
                false, true, false, true, false, true,
                true, true, true, true, true, true,
                false, true, false, false, true, true,
                true, true, false, true, true, true,
                true, false, true, true, false, true,
                false, false, true, true, true, false,
                false, false, false, true, true, false,
            ],
            // K12
            [
                false, true, true, true, false, true,
                false, true, false, true, true, true,
                false, false, false, true, true, true,
                true, true, false, true, false, true,
                true, false, false, true, false, true,
                false, false, false, true, true, false,
                false, true, true, true, true, true,
                true, false, true, false, false, true,
            ],
            // K13
            [
                true, false, false, true, false, true,
                true, true, true, true, false, false,
                false, true, false, true, true, true,
                false, true, false, false, false, true,
                true, true, true, true, true, false,
                true, false, true, false, true, true,
                true, false, true, false, false, true,
                false, false, false, false, false, true,
            ],
            // K14
            [
                false, true, false, true, true, true,
                true, true, false, true, false, false,
                false, false, true, true, true, false,
                true, true, false, true, true, true,
                true, true, true, true, false, false,
                true, false, true, true, true, false,
                false, true, true, true, false, false,
                true, true, true, false, true, false,
            ],
            // K15
            [
                true, false, true, true, true, true,
                true, true, true, false, false, true,
                false, false, false, true, true, false,
                false, false, true, true, false, true,
                false, false, true, true, true, true,
                false, true, false, false, true, true,
                true, true, true, true, false, false,
                false, false, true, false, true, false,
            ],
            // K16
            [
                true, true, false, false, true, false,
                true, true, false, false, true, true,
                true, true, false, true, true, false,
                false, false, true, false, true, true,
                false, false, false, false, true, true,
                true, false, false, false, false, true,
                false, true, true, true, true, true,
                true, true, false, true, false, true,
            ],
        ];
        assert_eq!(res, expected);
    }
}