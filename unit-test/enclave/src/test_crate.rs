use crate::utils::*;
use crate::TestResult;
use alloc::string::String;

static HASH_TEST_VEC: &[&str] = &[
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
];

static HASH_SHA256_TRUTH: &[&str] = &[
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
];

pub fn test_sha2_crate() -> TestResult {
    use sha2::{Digest, Sha256};
    let test_size = HASH_TEST_VEC.len();
    for i in 0..test_size {
        let input_str = String::from(HASH_TEST_VEC[i]);
        let hash = Sha256::digest(input_str.as_bytes());
        let expected = hex_to_bytes(HASH_SHA256_TRUTH[i]);
        if &hash[..] != expected.as_slice() {
            return Err("SHA256 hash mismatch");
        }
    }
    Ok(())
}

pub fn test_rand_crate() -> TestResult {
    use rand::{rngs::OsRng, TryRngCore};
    let random_u64_0 = OsRng.try_next_u64().unwrap();
    let random_u64_1 = OsRng.try_next_u64().unwrap();
    let random_u64_2 = OsRng.try_next_u64().unwrap();
    if random_u64_0 == random_u64_1 && random_u64_1 == random_u64_2 {
        return Err("rand crate produced same values");
    }
    Ok(())
}
