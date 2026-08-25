//! Known-answer tests (KATs).
//!
//! Every expectation in this file comes from an *independent* source --
//! never from this crate's own output. A roundtrip proves only that a
//! ciphertext decrypts with the same code that produced it; a KAT proves
//! the code matches a published standard.
//!
//! ## Provenance of the AES-256-GCM vectors
//!
//! All 18 primitive vectors are from the official NIST CAVP GCMVS test set
//! (`gcmEncryptExtIV256.rsp` and `gcmDecrypt256.rsp`, CAVS 14.0, generated
//! 2012-08-31), downloaded from csrc.nist.gov. Only `Keylen = 256`,
//! `IVlen = 96`, `Taglen = 128` cases are used, because encryptman always
//! derives a 256-bit key, generates 12-byte nonces, and appends a 16-byte
//! tag.
//!
//! Before being pinned here, every vector was independently recomputed
//! with OpenSSL 3.6 (via Node's `crypto` module, which is OpenSSL-backed)
//! and matched byte-for-byte, including the `FAIL` cases (tag mismatch
//! must be rejected). If any vector had been transcribed incorrectly, the
//! OpenSSL cross-check would have caught it.
//!
//! Note on "NIST ciphertexts through the crate's own format": the crate
//! derives the AES key with HKDF-SHA256 from a master key and a context
//! (`info = "encryptman:{context}"`), so an arbitrary NIST vector's raw
//! key cannot be routed through the public API. The tests therefore pin
//! two layers separately: the primitive layer against the raw-key NIST
//! vectors below, and the format layer (version byte, nonce position, tag
//! position, HKDF wiring) against the OpenSSL-computed fixture in
//! `format_fixture()`.
//!
//! ## Provenance of the format fixture
//!
//! The fixture was produced with an independent toolchain and pinned here:
//!
//! ```text
//! MK    = 000102...1e1f                     (32 bytes)
//! info  = "encryptman:kat"
//! DK    = HKDF-SHA256(ikm=MK, salt=<empty>, info)
//!        = 9daf4688501bba0f927961b02d247e709c665d55d9ab7b4f98da351da418f462
//!          ($ openssl kdf -keylen 32 -kdfopt digest:SHA256 \
//!              -kdfopt hexkey:<MK> -kdfopt hexinfo:656e63727970746d616e3a6b6174 HKDF)
//! C, T  = AES-256-GCM(DK, nonce=00112233445566778899aabb, plaintext)
//!          (Node crypto / OpenSSL 3)
//! packed = 0x01 || nonce || C || T
//! ```
//!
//! The `encrypt` fixture plaintext is the 43-byte string "The quick brown
//! fox jumps over the lazy dog"; `encrypt_empty` is the empty plaintext.

use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::{Aes256Gcm, Key};
use encryptman::{MasterKey, decrypt_bytes_with_context, encrypt_bytes_with_context};

/// One AES-256-GCM test case as published by NIST CAVP GCMVS.
struct GcmCase {
    /// Test-case identifier for traceability (file, PTlen/AADlen, Count).
    name: &'static str,
    key: &'static str,
    iv: &'static str,
    pt: &'static str,
    aad: &'static str,
    ct: &'static str,
    tag: &'static str,
}

/// NIST `gcmEncryptExtIV256.rsp`, Taglen=128, IVlen=96, Count=0 per section.
const NIST_ENCRYPT: &[GcmCase] = &[
    GcmCase {
        name: "PTlen=0   AADlen=0   Count=0",
        key: "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        iv: "516c33929df5a3284ff463d7",
        pt: "",
        aad: "",
        ct: "",
        tag: "bdc1ac884d332457a1d2664f168c76f0",
    },
    GcmCase {
        name: "PTlen=128 AADlen=0   Count=0",
        key: "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
        iv: "0d18e06c7c725ac9e362e1ce",
        pt: "2db5168e932556f8089a0622981d017d",
        aad: "",
        ct: "fa4362189661d163fcd6a56d8bf0405a",
        tag: "d636ac1bbedd5cc3ee727dc2ab4a9489",
    },
    GcmCase {
        name: "PTlen=128 AADlen=128 Count=0",
        key: "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b",
        iv: "ac93a1a6145299bde902f21a",
        pt: "2d71bcfa914e4ac045b2aa60955fad24",
        aad: "1e0889016f67601c8ebea4943bc23ad6",
        ct: "8995ae2e6df3dbf96fac7b7137bae67f",
        tag: "eca5aa77d51d4a0a14d9c51e1da474ab",
    },
    GcmCase {
        name: "PTlen=256 AADlen=384 Count=0",
        key: "dc776f0156c15d032623854b625c61868e5db84b7b6f9fbd3672f12f0025e0f6",
        iv: "67130951c4a57f6ae7f13241",
        pt: "9378a727a5119595ad631b12a5a6bc8a91756ef09c8d6eaa2b718fe86876da20",
        aad: "fd0920faeb7b212932280a009bac969145e5c316cf3922622c3705c3457c4e9f124b2076994323fbcfb523f8ed16d241",
        ct: "6d958c20870d401a3c1f7a0ac092c97774d451c09f7aae992a8841ff0ab9d60d",
        tag: "b876831b4ecd7242963b040aa45c4114",
    },
    GcmCase {
        name: "PTlen=408 AADlen=0   Count=0",
        key: "1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a",
        iv: "1f3afa4711e9474f32e70462",
        pt: "06b2c75853df9aeb17befd33cea81c630b0fc53667ff45199c629c8e15dce41e530aa792f796b8138eeab2e86c7b7bee1d40b0",
        aad: "",
        ct: "91fbd061ddc5a7fcc9513fcdfdc9c3a7c5d4d64cedf6a9c24ab8a77c36eefbf1c5dc00bc50121b96456c8cd8b6ff1f8b3e480f",
        tag: "30096d340f3d5c42d82a6f475def23eb",
    },
    GcmCase {
        name: "PTlen=408 AADlen=160 Count=0",
        key: "24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f",
        iv: "9ff18563b978ec281b3f2794",
        pt: "27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb158bd9abb3868fdc0d0b074b5f01b2c",
        aad: "adb5ec720ccf9898500028bf34afccbcaca126ef",
        ct: "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae82057ad55994cf59ad7f67c0fa5e85fab8",
        tag: "bc95c532fecc594c36d1550286a7a3f0",
    },
];

/// NIST `gcmDecrypt256.rsp`, Taglen=128, IVlen=96, Count=0 (or first PASS
/// case) per section. `pt` is the expected recovered plaintext.
const NIST_DECRYPT_PASS: &[GcmCase] = &[
    GcmCase {
        name: "PTlen=0   AADlen=0   Count=0",
        key: "f5a2b27c74355872eb3ef6c5feafaa740e6ae990d9d48c3bd9bb8235e589f010",
        iv: "58d2240f580a31c1d24948e9",
        pt: "",
        aad: "",
        ct: "",
        tag: "15e051a5e4a5f5da6cea92e2ebee5bac",
    },
    GcmCase {
        name: "PTlen=128 AADlen=0   Count=0",
        key: "4c8ebfe1444ec1b2d503c6986659af2c94fafe945f72c1e8486a5acfedb8a0f8",
        iv: "473360e0ad24889959858995",
        pt: "7789b41cb3ee548814ca0b388c10b343",
        aad: "",
        ct: "d2c78110ac7e8f107c0df0570bd7c90c",
        tag: "c26a379b6d98ef2852ead8ce83a833a7",
    },
    GcmCase {
        name: "PTlen=128 AADlen=128 Count=0",
        key: "54e352ea1d84bfe64a1011096111fbe7668ad2203d902a01458c3bbd85bfce14",
        iv: "df7c3bca00396d0c018495d9",
        pt: "85fc3dfad9b5a8d3258e4fc44571bd3b",
        aad: "7e968d71b50c1f11fd001f3fef49d045",
        ct: "426e0efc693b7be1f3018db7ddbb7e4d",
        tag: "ee8257795be6a1164d7e1d2d6cac77a7",
    },
    GcmCase {
        name: "PTlen=256 AADlen=384 Count=0",
        key: "42f6c25159b8655380f052dd5dad180e76813b60eb813665c5015f26cf32e8f1",
        iv: "7248a5ed48f4f1b4a9db3826",
        pt: "9a329cb45b0093e9c00615137dd7dbd1f8b525999af3bfc222315f41817717a7",
        aad: "8e3c74f127dbfe29ac4de0a7c3240ee8aa8d38a82f38ad6b480236c8cd4232057a5502e936bfe22225830fa195a8afce",
        ct: "26325c3463813a7d59d184a330ef80959637fa6db4f5db3062d3d2ec7e32d82a",
        tag: "4f39c63d4f215d5b39a58853d3842175",
    },
    GcmCase {
        name: "PTlen=408 AADlen=0   Count=0",
        key: "4433db5fe066960bdd4e1d4d418b641c14bfcef9d574e29dcd0995352850f1eb",
        iv: "0e396446655582838f27f72f",
        pt: "d602c06b947abe06cf6aa2c5c1562e29062ad6220da9bc9c25d66a60bd85a80d4fbcc1fb4919b6566be35af9819aba836b8b47",
        aad: "",
        ct: "b0d254abe43bdb563ead669192c1e57e9a85c51dba0f1c8501d1ce92273f1ce7e140dcfac94757fabb128caad16912cead0607",
        tag: "ffd0b02c92dbfcfbe9d58f7ff9e6f506",
    },
    GcmCase {
        name: "PTlen=408 AADlen=160 Count=2",
        key: "6450d4501b1e6cfbe172c4c8570363e96b496591b842661c28c2f6c908379cad",
        iv: "7e4262035e0bf3d60e91668a",
        pt: "17449e236ef5858f6d891412495ead4607bfae2a2d735182a2a0242f9d52fc5345ef912dbe16f3bb4576fe3bcafe336dee6085",
        aad: "f1c522f026e4c5d43851da516a1b78768ab18171",
        ct: "5a99b336fd3cfd82f10fb08f7045012415f0d9a06bb92dcf59c6f0dbe62d433671aacb8a1c52ce7bbf6aea372bf51e2ba79406",
        tag: "fe93b01636f7bb0458041f213e98de65",
    },
];

/// NIST `gcmDecrypt256.rsp`, Taglen=128, IVlen=96, `FAIL` cases: the tag
/// does not authenticate the ciphertext and decryption MUST error.
const NIST_DECRYPT_FAIL: &[GcmCase] = &[
    GcmCase {
        name: "PTlen=0   AADlen=0   Count=1",
        key: "e5a8123f2e2e007d4e379ba114a2fb66e6613f57c72d4e4f024964053028a831",
        iv: "51e43385bf533e168427e1ad",
        pt: "",
        aad: "",
        ct: "",
        tag: "38fe845c66e66bdd884c2aecafd280e6",
    },
    GcmCase {
        name: "PTlen=128 AADlen=0   Count=2",
        key: "c997768e2d14e3d38259667a6649079de77beb4543589771e5068e6cd7cd0b14",
        iv: "835090aed9552dbdd45277e2",
        pt: "",
        aad: "",
        ct: "9f6607d68e22ccf21928db0986be126e",
        tag: "f32617f67c574fd9f44ef76ff880ab9f",
    },
    GcmCase {
        name: "PTlen=128 AADlen=128 Count=2",
        key: "9a0343f850a6427120f764789ffec6d237447b898fbf51d2182f065d3861497d",
        iv: "3deef6f453dd70d92143adcd",
        pt: "",
        aad: "dbb8226a624520863db6897017b2a4f8",
        ct: "e93165935ac18e3a2845d15fe31a9286",
        tag: "f5fc50d18766bc3d9e16dd136d45816b",
    },
    GcmCase {
        name: "PTlen=256 AADlen=384 Count=2",
        key: "fff8747f38466904e99409f9dd8ed202f0e1a3e9e4768fe7f3a0b39c523bbbef",
        iv: "bd4ea7d286dfc0948145e37d",
        pt: "",
        aad: "d95546e9a05a8363f848419ce4d96f148a2d722f2bc15e5b6599b7eef1fb8ac52b3a2cf97cd6fecc67fa0bde6367b575",
        ct: "e8b7aed2ece9207ec158dc6d9b6fbf941197964820a9b0e5d8d30969c89b3e77",
        tag: "2379d116e1152171fbc184bc8b760845",
    },
    GcmCase {
        name: "PTlen=408 AADlen=0   Count=1",
        key: "28ae911ee685872d906de12d7696351df8ef2234a74a95efa4ea15b327338fe0",
        iv: "2fe6a815d4865181fade5fac",
        pt: "",
        aad: "",
        ct: "1168442ef64656ef6577fb42c1919c84aae856388e4db9945bb8c9b8412bbe6458bc400444d5d2bf2630f83468f66f9e46e790",
        tag: "b75f616fd1a3d6563b62b899e5a7e522",
    },
    GcmCase {
        name: "PTlen=408 AADlen=160 Count=0",
        key: "e9d381a9c413bee66175d5586a189836e5c20f5583535ab4d3f3e612dc21700e",
        iv: "23e81571da1c7821c681c7ca",
        pt: "",
        aad: "6f39c9ae7b8e8a58a95f0dd8ea6a9087cbccdfd6",
        ct: "a25f3f580306cd5065d22a6b7e9660110af7204bb77d370f7f34bee547feeff7b32a596fce29c9040e68b1589aad48da881990",
        tag: "5b6dcd70eefb0892fab1539298b92a4b",
    },
];

/// The OpenSSL-computed format fixture (see module docs for the exact
/// derivation commands).
mod format_fixture {
    /// Master key (000102...1f), also the IKM for HKDF.
    pub const MASTER_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    pub const CONTEXT: &str = "kat";
    /// HKDF-SHA256(ikm=MASTER_KEY, salt=empty, info="encryptman:kat").
    pub const DERIVED_KEY: &str =
        "9daf4688501bba0f927961b02d247e709c665d55d9ab7b4f98da351da418f462";
    /// Fixed nonce used in the fixture (a KAT fixture, never a live nonce).
    pub const NONCE: [u8; 12] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    ];
    pub const PLAINTEXT: &str = "The quick brown fox jumps over the lazy dog";
    /// packed = 0x01 || NONCE || C || T, computed with OpenSSL 3.
    pub const PACKED_HEX: &str = "0100112233445566778899aabbefc7f5282d01c27d55ce7a5896fbd0ffd7db97bd3bed48e99e9b7fae567e9b4a4ed01adcc3e5d47705deb86447060604c2f3697e254b384545c5b7";
    pub const PACKED_B64: &str = "AQARIjNEVWZ3iJmqu+/H9SgtAcJ9Vc56WJb70P/X25e9O+1I6Z6bf65WfptKTtAa3MPl1HcF3rhkRwYGBMLzaX4lSzhFRcW3";
    /// Empty-plaintext variant: packed = 0x01 || NONCE || T.
    pub const PACKED_EMPTY_HEX: &str = "0100112233445566778899aabbedae44f9fa86b27410fa8160bc1db67c";
    pub const PACKED_EMPTY_B64: &str = "AQARIjNEVWZ3iJmqu+2uRPn6hrJ0EPqBYLwdtnw=";
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex in KAT fixture"))
        .collect()
}

fn aes_key(c: &GcmCase) -> Key<Aes256Gcm> {
    Key::<Aes256Gcm>::try_from(hex(c.key).as_slice()).expect("32-byte key in KAT fixture")
}

fn nonce(bytes: &[u8]) -> Nonce<Aes256Gcm> {
    Nonce::<Aes256Gcm>::try_from(bytes).expect("12-byte nonce in KAT fixture")
}

/// Encrypting NIST plaintexts with the NIST key/nonce must reproduce the
/// NIST ciphertext and tag byte-for-byte (SP 800-38D / CAVP GCMVS).
#[test]
fn primitive_encrypt_matches_nist() {
    for c in NIST_ENCRYPT {
        let cipher = Aes256Gcm::new(&aes_key(c));
        let pt = hex(c.pt);
        let aad = hex(c.aad);
        let output = cipher
            .encrypt(
                &nonce(&hex(c.iv)),
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .unwrap_or_else(|_| panic!("NIST encrypt case failed: {}", c.name));

        let ct_len = c.ct.len() / 2;
        assert_eq!(
            output.len(),
            ct_len + 16,
            "{}: tag must be 16 bytes",
            c.name
        );
        assert_eq!(&output[..ct_len], hex(c.ct), "{}: ciphertext", c.name);
        assert_eq!(&output[ct_len..], hex(c.tag), "{}: tag", c.name);
    }
}

/// Decrypting NIST ciphertexts with the NIST key/nonce must recover the
/// published plaintext.
#[test]
fn primitive_decrypt_recovers_nist_plaintext() {
    for c in NIST_DECRYPT_PASS {
        let cipher = Aes256Gcm::new(&aes_key(c));
        let mut input = hex(c.ct);
        input.extend_from_slice(&hex(c.tag));
        let aad = hex(c.aad);
        let plaintext = cipher
            .decrypt(
                &nonce(&hex(c.iv)),
                Payload {
                    msg: &input,
                    aad: &aad,
                },
            )
            .unwrap_or_else(|_| panic!("NIST decrypt case failed: {}", c.name));
        assert_eq!(plaintext, hex(c.pt), "{}: plaintext", c.name);
    }
}

/// NIST's own FAIL cases (tag does not authenticate) must error.
#[test]
fn primitive_rejects_nist_fail_vectors() {
    for c in NIST_DECRYPT_FAIL {
        let cipher = Aes256Gcm::new(&aes_key(c));
        let mut input = hex(c.ct);
        input.extend_from_slice(&hex(c.tag));
        let aad = hex(c.aad);
        let result = cipher.decrypt(
            &nonce(&hex(c.iv)),
            Payload {
                msg: &input,
                aad: &aad,
            },
        );
        assert!(result.is_err(), "{}: FAIL vector must not decrypt", c.name);
    }
}

/// A single flipped tag byte must make decryption fail (tag is checked,
/// not merely appended).
#[test]
fn primitive_tag_is_checked() {
    for c in NIST_DECRYPT_PASS {
        let cipher = Aes256Gcm::new(&aes_key(c));
        let mut input = hex(c.ct);
        let mut tag = hex(c.tag);
        tag[0] ^= 0x01;
        input.extend_from_slice(&tag);
        let aad = hex(c.aad);
        let result = cipher.decrypt(
            &nonce(&hex(c.iv)),
            Payload {
                msg: &input,
                aad: &aad,
            },
        );
        assert!(result.is_err(), "{}: flipped tag byte must fail", c.name);
    }
}

fn fixture_master_key() -> MasterKey {
    MasterKey::from_bytes(format_fixture::MASTER_KEY)
}

/// The crate's full decrypt pipeline (base64 decode -> version check ->
/// nonce split -> HKDF derivation -> AES-256-GCM) must recover the
/// OpenSSL-computed plaintext from the pinned fixture.
#[test]
fn crate_format_decrypts_independent_fixture() {
    let mk = fixture_master_key();

    let via_bytes = decrypt_bytes_with_context(
        &mk,
        format_fixture::CONTEXT,
        &hex(format_fixture::PACKED_HEX),
    )
    .expect("fixture must decrypt");
    assert_eq!(via_bytes, format_fixture::PLAINTEXT.as_bytes());

    let via_b64 = decrypt_bytes_with_context(
        &mk,
        format_fixture::CONTEXT,
        &encryptman::Encoding::Standard
            .decode(format_fixture::PACKED_B64)
            .expect("fixture base64 must decode"),
    )
    .expect("base64 fixture must decrypt");
    assert_eq!(via_b64, format_fixture::PLAINTEXT.as_bytes());

    let empty = decrypt_bytes_with_context(
        &mk,
        format_fixture::CONTEXT,
        &hex(format_fixture::PACKED_EMPTY_HEX),
    )
    .expect("empty-plaintext fixture must decrypt");
    assert!(empty.is_empty());

    let empty_b64 = decrypt_bytes_with_context(
        &mk,
        format_fixture::CONTEXT,
        &encryptman::Encoding::Standard
            .decode(format_fixture::PACKED_EMPTY_B64)
            .expect("empty-plaintext base64 must decode"),
    )
    .expect("empty-plaintext base64 fixture must decrypt");
    assert!(empty_b64.is_empty());
}

/// The packed layout must be exactly `version (0x01) || 12-byte nonce ||
/// ciphertext || 16-byte tag`, byte for byte. A future refactor that
/// reorders the format fails here.
#[test]
fn crate_format_layout_kat() {
    let packed = hex(format_fixture::PACKED_HEX);
    let nonce_len = 12;
    let tag_len = 16;
    let pt_len = format_fixture::PLAINTEXT.len();

    assert_eq!(packed.len(), 1 + nonce_len + pt_len + tag_len);
    assert_eq!(packed[0], 0x01, "version byte");
    assert_eq!(
        &packed[1..1 + nonce_len],
        format_fixture::NONCE,
        "nonce must occupy bytes 1..=12"
    );
    assert_eq!(
        &packed[packed.len() - tag_len..],
        hex("6447060604c2f3697e254b384545c5b7"),
        "tag must occupy the final 16 bytes"
    );

    // The fixture must be a valid Standard base64 string that decodes to
    // the exact packed bytes.
    let decoded = encryptman::Encoding::Standard
        .decode(format_fixture::PACKED_B64)
        .expect("fixture base64 must decode");
    assert_eq!(decoded, packed);
}

/// An unrecognized version byte must be rejected before any crypto runs.
#[test]
fn crate_format_checks_version_byte() {
    let mk = fixture_master_key();
    let mut packed = hex(format_fixture::PACKED_HEX);
    packed[0] = 0x02;
    let err = decrypt_bytes_with_context(&mk, format_fixture::CONTEXT, &packed).unwrap_err();
    assert!(matches!(
        err,
        encryptman::CryptoError::UnsupportedVersion(0x02)
    ));

    packed[0] = 0x00;
    let err = decrypt_bytes_with_context(&mk, format_fixture::CONTEXT, &packed).unwrap_err();
    assert!(matches!(
        err,
        encryptman::CryptoError::UnsupportedVersion(0x00)
    ));
}

/// Corrupting the ciphertext, the tag, or the nonce must all produce the
/// generic `DecryptionFailed` error -- never plaintext, never a panic.
#[test]
fn crate_format_rejects_tampered_fixture() {
    let mk = fixture_master_key();
    let packed = hex(format_fixture::PACKED_HEX);

    // Flip every byte of the ciphertext+tag region (skip the version byte,
    // which is covered by its own test).
    for i in 1..packed.len() {
        let mut tampered = packed.clone();
        tampered[i] ^= 0x01;
        let result = decrypt_bytes_with_context(&mk, format_fixture::CONTEXT, &tampered);
        assert!(
            matches!(result, Err(encryptman::CryptoError::DecryptionFailed)),
            "byte {} must fail with DecryptionFailed, got {:?}",
            i,
            result
        );
    }
}

/// The wrong key or the wrong context must fail with the same generic
/// error (no oracle: the caller cannot tell which input was wrong).
#[test]
fn crate_format_wrong_key_and_context_fail() {
    let mk = fixture_master_key();
    let packed = hex(format_fixture::PACKED_HEX);

    let wrong_key = MasterKey::from_bytes([0x42; 32]);
    let err = decrypt_bytes_with_context(&wrong_key, format_fixture::CONTEXT, &packed).unwrap_err();
    assert!(matches!(err, encryptman::CryptoError::DecryptionFailed));

    let err = decrypt_bytes_with_context(&mk, "not-kat", &packed).unwrap_err();
    assert!(matches!(err, encryptman::CryptoError::DecryptionFailed));
}

/// Reverse interop: the crate's encrypt output must decrypt with the
/// OpenSSL-computed derived key. This pins the encrypt path (random nonce
/// generation, packing) to the independent implementation.
#[test]
fn crate_encrypt_output_decrypts_with_independent_key() {
    let mk = fixture_master_key();
    let cipher = Aes256Gcm::new(
        &Key::<Aes256Gcm>::try_from(hex(format_fixture::DERIVED_KEY).as_slice())
            .expect("32-byte derived key"),
    );

    let packed = encrypt_bytes_with_context(
        &mk,
        format_fixture::CONTEXT,
        format_fixture::PLAINTEXT.as_bytes(),
    )
    .expect("encrypt must succeed");

    assert_eq!(packed[0], 0x01, "version byte");
    let nonce = &nonce(&packed[1..1 + format_fixture::NONCE.len()]);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &packed[1 + format_fixture::NONCE.len()..],
                aad: &[],
            },
        )
        .expect("OpenSSL-derived key must decrypt crate output");
    assert_eq!(plaintext, format_fixture::PLAINTEXT.as_bytes());
}

/// Truncated ciphertexts must be rejected with `CiphertextTooShort`, and
/// garbage base64 with `InvalidBase64`, before any crypto runs.
#[test]
fn crate_format_rejects_truncated_and_garbage_input() {
    let mk = fixture_master_key();

    let err = decrypt_bytes_with_context(&mk, format_fixture::CONTEXT, &[]).unwrap_err();
    assert!(matches!(
        err,
        encryptman::CryptoError::CiphertextTooShort { .. }
    ));

    let err = decrypt_bytes_with_context(&mk, format_fixture::CONTEXT, &[0x01]).unwrap_err();
    assert!(matches!(
        err,
        encryptman::CryptoError::CiphertextTooShort { .. }
    ));

    let err = decrypt_bytes_with_context(
        &mk,
        format_fixture::CONTEXT,
        &hex(format_fixture::PACKED_HEX)[..13],
    )
    .unwrap_err();
    assert!(matches!(
        err,
        encryptman::CryptoError::CiphertextTooShort { .. }
    ));

    let err = encryptman::Encoding::Standard
        .decode("!!!not base64!!!")
        .expect_err("garbage must not decode");
    assert!(matches!(err, base64::DecodeError::InvalidByte(..)));
}
