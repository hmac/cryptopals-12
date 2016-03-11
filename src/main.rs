extern crate rustc_serialize;
extern crate crypto;
extern crate rand;
use crypto::aes;
use rustc_serialize::base64::FromBase64;
use rand::random;

fn main() {
    let oracle = Oracle {key: generate_key()};
    let blocksize = guess_block_size(&oracle);
    let mode = determine_cipher_mode(&oracle);
    println!("block size detected is {}", blocksize);
    println!("cipher mode detected is {}", match mode {
        CipherMode::ECB => "ECB",
        CipherMode::CBC => "CBC"
    });
    let mut decrypted_data: Vec<u8> = Vec::new();

    let block = determine_first_block(&oracle, blocksize);
    println!("{:?}", block);

    //let byte = determine_second_block_byte_n(&oracle, blocksize, decrypted_data.as_slice());
    //decrypted_data.push(byte);
    //println!("{:?}", String::from_utf8_lossy(decrypted_data.as_slice()));

    //for i in 0..150 {
        //let byte = determine_second_block_byte_n(&oracle, blocksize, decrypted_data.as_slice());
        //decrypted_data.push(byte);
        //println!("{:?} {:?}", i, String::from_utf8_lossy(decrypted_data.as_slice()));
    //}
    //println!("{}", String::from_utf8_lossy(decrypted_data.as_slice()));
}

fn determine_first_byte(oracle: &Oracle, blocksize: u8) -> u8 {
    let stem = vec![0u8; blocksize as usize - 1]; // our string which we'll pass to the oracle
    println!("stem: {:?}", stem);

    // generate the dictionary of possible outputs that the oracle could produce
    let mut dict: Vec<Vec<u8>> = Vec::new();
    for i in 0..255 {
        let mut data = stem.clone(); // AAAAAAA
        data.push(i);                // AAAAAAAT <- the one byte from the secret string
        let ciphertext = oracle.encrypt(data.as_slice());
        let first_block = &ciphertext[0..(blocksize as usize)];
        dict.push(first_block.to_vec());
    }

    // now we encrypt the stem to get the real ciphertext
    let ciphertext = oracle.encrypt(stem.as_slice());
    let first_block = &ciphertext[0..(blocksize as usize)];

    println!("real ciphertext: {:?}", first_block);

    // now we match the real block to the entry in the dict
    for i in 0..255 {
        println!("candidate ciphertext: {:?}", dict[i]);
        // if the blocks match, i is the first byte of the secret string
        if first_block == dict[i].as_slice() { return i as u8 }
    }
    panic!("no match found!");
}

fn determine_first_block(oracle: &Oracle, blocksize: u8) -> Vec<u8> {
    let mut decrypted_block = Vec::new();

    // n is the index of the byte we're trying to decrypt
    'outer: for n in 0..blocksize as usize {
        // we'll need a stem that is of length blocksize -n -1
        let stem = vec![0u8; blocksize as usize - n - 1];

        // generate the dictionary
        let mut dict: Vec<Vec<u8>> = Vec::new();
        for i in 0..255 {
            let mut data = stem.clone();
            data.extend_from_slice(decrypted_block.as_slice()); // push on any bytes found so far
            data.push(i);
            let ciphertext = oracle.encrypt(data.as_slice());
            let first_block = &ciphertext[0..(blocksize as usize)];
            dict.push(first_block.to_vec());
        }

        let ciphertext = oracle.encrypt(stem.as_slice());
        let first_block = &ciphertext[0..(blocksize as usize)];

        for i in 0..255 {
            if first_block == dict[i].as_slice() {
                decrypted_block.push(i as u8);
                continue 'outer;
            }
        }
        panic!("no match found!")
    }
    return decrypted_block;
}

fn determine_second_block_byte_n(oracle: &Oracle, blocksize: u8, known_bytes: &[u8]) -> u8 {
    let n = known_bytes.len() as u8 % blocksize;
    let block_offset: u8 = known_bytes.len() as u8 / blocksize;
    let bs = blocksize as usize;
    let stem = vec![0u8, blocksize-n-1];
    let mut letter_bytes: Vec<Vec<u8>> = Vec::new();

    let data_stem = create_stem(known_bytes, blocksize, n);

    for i in 0..255 {
        let mut data = data_stem.clone();
        data.push(i);
        let ct = oracle.encrypt(data.as_slice());
        let block = &ct[0..bs as usize];
        letter_bytes.push(block.to_vec());
    }

    // Get the actual block value
    let ct = oracle.encrypt(stem.as_slice());
    let bo = block_offset as usize;
    let index = (bo * bs)..((bo + 1) * bs);
    let real_block = &ct[index];
    //let real_block = &ct[0..2]; // hack to get this to compile

    // Match actual to generated
    for i in 0u8..255 {
        if real_block == letter_bytes[i as usize].as_slice() {
            return i;
        }
    }
    0u8
}

// The data stem is the last (blocksize-1) bytes in known_bytes
// If there are fewer than (blocksize-1) known bytes, then the beginning of the stem
// is padded with 0u8 to bring it back to (blocksize-1) in length
fn create_stem(known_bytes: &[u8], blocksize: u8, n: u8) -> Vec<u8> {
    let bs = blocksize as usize;
    let start = if known_bytes.len() < bs { 0 } else { known_bytes.len() - bs + 1};

    let mut data_stem = known_bytes[start..].to_vec();
    if data_stem.len() < (bs - 1) {
        data_stem.reverse();
        for _ in 0..(blocksize-n-1) {
            data_stem.push(0u8);
        }
        data_stem.reverse();
    }
    data_stem
}

fn determine_unknown_string_length(oracle: &Oracle, blocksize: u8) -> usize {
    0
}

fn guess_block_size(oracle: &Oracle) -> u8 {
    // add bytes one at a time
    // when the ct size increases,
    // it will increase by 1 block size
    let prev_len = oracle.encrypt(vec![0].as_slice()).len();
    for i in 1..64 {
        let len = oracle.encrypt(vec![0; i].as_slice()).len();
        //let len = oracle.encrypt(Vec::from_elem(i, 0).as_slice()).len();
        if len > prev_len {
            return (len - prev_len) as u8;
        }
    }
    return 0u8;
}

fn generate_key() -> Vec<u8> {
    let mut key = Vec::with_capacity(16);
    for _ in 0..16 {
        key.push(random::<u8>());
    }
    key
}

struct Oracle {
    key: Vec<u8>
}

trait OracleMethods {
    fn encrypt(&self, _data: &[u8]) -> Vec<u8>;
}

impl OracleMethods for Oracle {
    fn encrypt(&self, _data: &[u8]) -> Vec<u8> {
        let unkown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK".as_bytes().from_base64().ok().expect("base64 failure");
        let mut data = _data.to_vec();
        data.extend_from_slice(unkown_string.as_slice());
        aes::ecb::encrypt_128(data.as_slice(), self.key.as_slice())
    }
}

enum CipherMode {
    ECB,
    CBC
}

fn determine_cipher_mode(oracle: &Oracle) -> CipherMode {
    let data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes();
    let ct = oracle.encrypt(data);
    let sample = &ct[32..37];
    let repeats = substr_repeats(ct.as_slice(), sample);
    if repeats > 1 {
        CipherMode::ECB
    } else {
        CipherMode::CBC
    }
}

fn substr_repeats(haystack: &[u8], needle: &[u8]) -> u8 {
    let mut repeats = 0u8;
    let mut c = 0;
    for i in 0..haystack.len() {
        if haystack[i] == needle[c] {
            c = c+1;
        }
        else {
            c = 0;
        }
        if c == needle.len() {
            repeats = repeats + 1;
            c = 0;
        }
    }
    return repeats;
}
