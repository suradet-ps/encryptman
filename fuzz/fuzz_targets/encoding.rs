#![no_main]

use encryptman::Encoding;
use libfuzzer_sys::fuzz_target;

// Feed arbitrary bytes through both base64 decoders.
//
// Invariants:
// - no panic, no hang, no allocation blowup on any input;
// - for every input that decodes, re-encoding must produce the exact
//   original bytes (decoding is a true inverse of encoding).
fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);

    for encoding in [Encoding::Standard, Encoding::UrlSafeNoPad] {
        if let Ok(bytes) = encoding.decode(&input) {
            let reencoded = encoding.encode(&bytes);
            let round = encoding
                .decode(&reencoded)
                .expect("encode output must always decode");
            assert_eq!(round, bytes, "decode(encode(x)) != x");
        }
    }
});