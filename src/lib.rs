use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use log::*;
use pelite::{
    pe32::{Pe, PeFile},
    resources::Name,
};
use pretty_hex::*;

use thiserror::Error;

mod constants;

#[derive(Debug, Error)]
pub enum Error {
    #[error("input file is not a Windows PE file")]
    InvalidFile,
    #[error("could not read metadata: {0}")]
    InvalidMetadata(&'static str),
    #[error("error occurred while trying to parse input file")]
    Parsing(#[from] pelite::Error),
    #[error("error occurred while trying to find `RES_UPDATE_INFO` resource")]
    NoResource(#[from] pelite::resources::FindError),
}

/// Takes the input PE data, parses it as a 32-bit PE, and if successful returns
/// the `RES_UPDATE_INFO` data.
pub fn update_info_from_pe(pe_data: &[u8]) -> Result<&[u8], Error> {
    let pe_file = PeFile::from_bytes(pe_data)?;
    let resources = pe_file.resources()?;

    resources
        .find_resource(&[Name::Id(23), Name::Str("RES_UPDATE_INFO")])
        .map_err(Error::from)
}

/// Decrypts the input `update_info` and returns its decrypted form.
pub fn decrypt(update_info: &[u8]) -> Result<Vec<u8>, Error> {
    // First 4 bytes of the update info are a timestamp
    let mut decryptor = Decryptor::default();
    decryptor.inflate_timestamp(u32::from_le_bytes(update_info[..4].try_into().unwrap()));

    // There's a blob of size 0x5c at the end of the update info that describes
    // the update
    let mut reader = Cursor::new(&update_info[0x100_004..]);
    let firmware_size = reader
        .read_u32::<LittleEndian>()
        .map_err(|_| Error::InvalidMetadata("firmware_size"))? as usize;
    eprintln!("Maybe firmware size: {:#x}", firmware_size);
    let firmware_size = 0x100_000;

    // // No idea if this is actually a string count
    // let maybe_string_count = reader
    //     .read_u32::<LittleEndian>()
    //     .map_err(|_| Error::InvalidMetadata("string_count"))?;

    // let mut str_buffer = Vec::with_capacity(0x100);
    // for _ in 0..maybe_string_count as usize {
    //     str_buffer.clear();
    //     loop {
    //         let c = reader
    //             .read_u8()
    //             .map_err(|_| Error::InvalidMetadata("string_table"))?;
    //         if c == 0x0 {
    //             break;
    //         }

    //         str_buffer.push(c);
    //     }
    //     eprintln!(
    //         "{}",
    //         std::str::from_utf8(str_buffer.as_slice())
    //             .map_err(|_| Error::InvalidMetadata("string_in_string_table"))?
    //     );
    // }

    Ok(decryptor.decrypt_data(&update_info[4..firmware_size + 4]))
}

struct Decryptor {
    key: [u8; 0x300],
}

impl Decryptor {
    fn set_key(&mut self, key: &[u8; 56]) {
        let mut scrambled_table = key.clone();
        // drop the input key so we don't accidentally use it from here on out
        drop(key);

        // the program technically reads DWORDS from the KEY_CONFIG and increments
        // their pointer by 1 DWORD per iteration... but we only need to read out
        // the MSB and this simplifies things
        for i in 0..16 {
            let rounds = if constants::KEY_CONFIG[i * 4] == 2 {
                2
            } else {
                1
            };

            for _ in 0..rounds {
                let mut temp_byte = scrambled_table[0];
                scrambled_table.copy_within(1..=27, 0);
                scrambled_table[27] = temp_byte;

                temp_byte = scrambled_table[28];
                scrambled_table.copy_within(29.., 28);
                scrambled_table[55] = temp_byte;
            }

            for key_config_idx in 0..48 {
                let scrambled_idx = (constants::KEY_CONFIG2[key_config_idx] as usize) - 1;

                let swaptable_idx = key_config_idx + (i * 48);
                self.key[swaptable_idx] = scrambled_table[scrambled_idx];
            }
        }
    }

    fn decrypt(&mut self, outbuf: &mut [u8], is_encrypt: bool) {
        let mut multiplier = 0x0;
        let mut remaining_data = 15;
        let mut scratch_buffer = [0u8; 48];
        let mut done = false;
        if !is_encrypt {
            multiplier = 0xF;
        }

        while !done {
            for i in 0..(48 / 6) {
                trace!("");
                trace!("round {}", i);
                trace!("\n{} start temp:\n{:?}", i, (&scratch_buffer).hex_dump());
                trace!("\ninflated data: {:?}\n", outbuf.hex_dump());

                trace!("multiplier: 0x{:X}", multiplier);

                const BYTES_PER_ROUND: usize = 6;
                // We do 6 bytes per round
                let iidx = i * BYTES_PER_ROUND;

                // We read 6 bytes at a time
                for j in 0..BYTES_PER_ROUND {
                    debug!("{}, {}", iidx, j);
                    debug!("config: {:#x}", constants::ENCRYPTION_CONFIG[iidx + j]);
                    let rhs_idx = (constants::ENCRYPTION_CONFIG[iidx + j] as usize) + 31;
                    debug!("inflated_data idx: {:#x}", rhs_idx);
                    let rhs = outbuf[rhs_idx];
                    debug!("inflated_data : {:#x}", rhs);
                    let lhs_idx = (48 * multiplier) + iidx + j;
                    debug!("key idx: {:#x}", lhs_idx);
                    let lhs = self.key[lhs_idx];
                    debug!("key : {:#x}", lhs);
                    let result = lhs ^ rhs;
                    debug!("result: {:#x}", result);
                    let result_idx = iidx + j;

                    debug!("result idx: {:#x}", result_idx);
                    scratch_buffer[result_idx] = result;

                    debug!("");
                }
                debug!("\n{} temp:\n{:?}", i, (&scratch_buffer).hex_dump());
            }
            debug!("temp:\n{:?}", (&scratch_buffer).hex_dump());

            macro_rules! combine {
                ($offset:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr) => {{
                    // these get subtracted by 4 since in the original code there
                    // is a `this` pointer stored between data buffers. We don't
                    // have that.
                    let a = $a - 4;
                    let b = $b - 4;
                    let c = $c - 4;
                    let d = $d - 4;
                    let e = $e - 4;
                    let f = $f - 4;

                    debug!(
                        "a={}, val={:#x}, shifted={:#x}",
                        $a,
                        scratch_buffer[a] as u32,
                        (scratch_buffer[a] as u32 * 32) + 2
                    );
                    debug!(
                        "b={}, val={:#x}, shifted={:#x}",
                        $b,
                        scratch_buffer[b] as u32,
                        (scratch_buffer[b] as u32 * 16) + 2
                    );
                    debug!(
                        "c={}, val={:#x}, shifted={:#x}",
                        $c,
                        scratch_buffer[c] as u32,
                        (scratch_buffer[c] as u32 * 8 + 2)
                    );
                    debug!(
                        "d={}, val={:#x}, shifted={:#x}",
                        $d,
                        scratch_buffer[d] as u32,
                        (scratch_buffer[d] as u32 * 4 + 2)
                    );
                    debug!(
                        "e={}, val={:#x}, shifted={:#x}",
                        $e,
                        scratch_buffer[e] as u32,
                        (scratch_buffer[e] as u32 * 2 + 2)
                    );
                    debug!(
                        "f={}, val={:#x}, shifted={:#x}",
                        $f,
                        scratch_buffer[f] as u32,
                        (scratch_buffer[f] as u32 + 2)
                    );
                    let mystery_idx = ((scratch_buffer[a] as u32 * 32 + 2)
                        | (scratch_buffer[b] as u32 * 16 + 2)
                        | (scratch_buffer[c] as u32 * 8 + 2)
                        | (scratch_buffer[d] as u32 * 4 + 2)
                        | (scratch_buffer[e] as u32 * 2 + 2)
                        | (scratch_buffer[f] as u32 + 2)) as usize;
                    debug!("offset: {:}", $offset);
                    debug!("full idx: {:#x}", mystery_idx + $offset);

                    debug!("{:#X?}", &constants::ENCRYPTION_CONFIG2[$offset + mystery_idx..][..4]);

                    let val = u32::from_le_bytes(constants::ENCRYPTION_CONFIG2[$offset + mystery_idx..][..4].try_into().unwrap());
                    debug!("{:#x}", val);
                    val
                }};
            }

            let temp1 = combine!(0, 4, 9, 5, 6, 7, 8);
            let temp2 = combine!(0x100, 10, 15, 11, 12, 13, 14);
            let temp3 = combine!(0x200, 16, 21, 17, 18, 19, 20);
            let temp4 = combine!(0x300, 22, 27, 23, 24, 25, 26);
            let temp5 = combine!(0x400, 28, 33, 29, 30, 31, 32);
            let temp6 = combine!(0x500, 34, 39, 35, 36, 37, 38);
            let temp7 = combine!(0x600, 40, 45, 41, 42, 43, 44);
            let temp8 = combine!(0x700, 46, 51, 47, 48, 49, 50);
            let mut temp_key_material: Vec<u8> = [
                temp1.to_le_bytes(),
                temp2.to_le_bytes(),
                temp3.to_le_bytes(),
                temp4.to_le_bytes(),
                temp5.to_le_bytes(),
                temp6.to_le_bytes(),
                temp7.to_le_bytes(),
                temp8.to_le_bytes(),
            ]
            .iter()
            .flatten()
            .cloned()
            .collect();

            debug!(
                "temp_key_material before append: {:?}",
                temp_key_material.hex_dump()
            );
            temp_key_material.extend_from_slice(&scratch_buffer);
            debug!("temp_key_material: {:?}", temp_key_material.hex_dump());

            debug!("\n\noutput:{:?}\n\n", outbuf.hex_dump());
            let mut output_buffer_offset = 0;
            if remaining_data == 0 {
                for _i in 0..8 {
                    debug!("\n\noutput BEFORE:{:?}\n\n", outbuf.hex_dump());

                    outbuf[output_buffer_offset + 0] ^= temp_key_material
                        [constants::ENCRYPTION_CONFIG3[output_buffer_offset] as usize - 1];
                    outbuf[output_buffer_offset + 1] ^= temp_key_material
                        [constants::ENCRYPTION_CONFIG3[output_buffer_offset + 1] as usize - 1];
                    outbuf[output_buffer_offset + 2] ^= temp_key_material
                        [constants::ENCRYPTION_CONFIG3[output_buffer_offset + 2] as usize - 1];
                    outbuf[output_buffer_offset + 3] ^= temp_key_material
                        [constants::ENCRYPTION_CONFIG3[output_buffer_offset + 3] as usize - 1];
                    output_buffer_offset += 4;

                    debug!("\n\noutput AFTER:{:?}\n\n", outbuf.hex_dump());
                }
            } else {
                for i in 0..8 {
                    debug!("");
                    debug!("round: {}", i);
                    for (first, second) in (0x1c..=0x1f).zip(0..4) {
                        debug!("\n\noutput BEFORE:{:?}\n\n", outbuf.hex_dump());
                        debug!("swapping {:#x} with {:#x}", first, second);

                        let original_byte_idx = first + output_buffer_offset + 4;

                        debug!("original byte index: {:#x}", original_byte_idx);
                        let original_byte = outbuf[original_byte_idx];
                        debug!("original byte: {:#x}", original_byte);

                        let constant =
                            constants::ENCRYPTION_CONFIG3[output_buffer_offset + second] as usize;

                        debug!("curr byte: {:#x}", outbuf[output_buffer_offset + second]);
                        debug!("constant: {:#x}", constant);
                        debug!("xor rhs: {:#x}", temp_key_material[constant - 1]);
                        debug!(
                            "{:#x} ^ {:#x}",
                            outbuf[output_buffer_offset + second],
                            temp_key_material[constant - 1]
                        );

                        let new_byte =
                            outbuf[output_buffer_offset + second] ^ temp_key_material[constant - 1];

                        debug!("new byte: {:#x}", new_byte);

                        let new_idx = original_byte_idx;
                        debug!("new byte goes to {:#X}", new_idx);
                        debug!("old byte goes to {:#X}", output_buffer_offset + second);
                        outbuf[new_idx] = new_byte;
                        outbuf[output_buffer_offset + second] = original_byte;

                        debug!("\n\noutput AFTER:{:?}\n\n", outbuf.hex_dump());
                        debug!("");
                    }

                    output_buffer_offset += 4;

                    debug!("");
                }
            }

            done = remaining_data == 0;
            remaining_data -= 1;
            if is_encrypt {
                multiplier += 1;
            } else {
                multiplier = multiplier.saturating_sub(1);
            }
        }
    }

    pub fn inflate_timestamp(&mut self, timestamp: u32) {
        // Convert the timestamp to a string
        let date = Utc.timestamp(timestamp as i64, 0);
        let formatted_date = date.format("%Y%m%d%H%M%S").to_string();
        let mut outbuf = [0u8; 64];

        // There are 4 different rounds for setting up the timestamp key
        let mut date_bytes = formatted_date.as_bytes().iter().cloned();
        let mut curr_byte = date_bytes.next().unwrap();
        for swap_table in 0..4 {
            self.set_key(&constants::TIMESTAMP_TABLES[swap_table]);
            for byte_idx in 0..8 {
                for bit_idx in 0..8 {
                    let bit_value = (curr_byte >> (7 - bit_idx)) & 1;
                    let outbuf_idx = (byte_idx * 8) + bit_idx;
                    outbuf[outbuf_idx] = bit_value ^ outbuf[outbuf_idx];
                }

                if let Some(next) = date_bytes.next() {
                    curr_byte = next;
                } else {
                    curr_byte = 0x0;
                }
            }

            self.decrypt(&mut outbuf, true);
        }

        self.set_key(&outbuf[..56].try_into().unwrap());
    }

    pub fn decrypt_data(&mut self, encrypted_data: &[u8]) -> Vec<u8> {
        let mut decrypted = vec![0u8; encrypted_data.len()];
        let mut inflated: [u8; 64] = [0u8; 64];

        let mut output_idx = 0;
        let mut remaining_data = encrypted_data.len();
        loop {
            let mut block_size = std::cmp::min(8, remaining_data);
            remaining_data = remaining_data.saturating_sub(block_size);
            //println!("{:#x}", remaining_data);
            for i in 0..block_size {
                let encrypted_bytes = encrypted_data[i + output_idx];
                let bit_idx = i * 8;
                inflated[bit_idx] = encrypted_bytes >> 7;
                inflated[bit_idx + 1] = (encrypted_bytes >> 6) & 1;
                inflated[bit_idx + 2] = (encrypted_bytes >> 5) & 1;
                inflated[bit_idx + 3] = (encrypted_bytes >> 4) & 1;
                inflated[bit_idx + 4] = (encrypted_bytes >> 3) & 1;
                inflated[bit_idx + 5] = (encrypted_bytes >> 2) & 1;
                inflated[bit_idx + 6] = (encrypted_bytes >> 1) & 1;
                inflated[bit_idx + 7] = encrypted_bytes & 0x1;
            }

            self.decrypt(&mut inflated, false);

            let mut curr_inflated_idx = 0;
            while block_size > 0 {
                block_size -= 1;

                let inflated = &mut inflated[curr_inflated_idx * 8..];
                // we need to reassemble 8 bits
                for shift in 0..8 {
                    decrypted[output_idx] |= inflated[7 - shift] << shift;
                }

                // println!("{:#X}", deobfuscated[output_idx]);
                output_idx += 1;
                curr_inflated_idx += 1;
            }

            if remaining_data == 0 {
                return decrypted;
            }
        }
    }
}

impl Default for Decryptor {
    fn default() -> Decryptor {
        Self { key: [0u8; 0x300] }
    }
}
