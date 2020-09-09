//! Implementation of PSSST: Packet Security for Stateless Server Transactions
//!
//! There are currently no docs.

#![forbid(unsafe_code, future_incompatible, rust_2018_idioms)]
#![deny(nonstandard_style)]
//#![warn(missing_docs, missing_doc_code_examples, unreachable_pub)]

use aes_gcm::{AeadInPlace, Aes128Gcm, NewAead};
use byteorder::{BigEndian, ByteOrder};
use hacl_star::curve25519;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use std::convert::TryInto;

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Ciphersuite {
    X25519_AESGCM128 = 1,
}

const AEAD_TAG_LEN: usize = 16;
const KX_PUB_LEN: usize = 32;
const KX_PRIV_LEN: usize = 32;

#[derive(Clone, Copy, Debug)]
pub enum Error {
    Truncated,
    InsufficientBuffer(usize),
    UnexpectedCiphersuite,
    UnexpectedResponse,
    UnexpectedHeader,
    DecryptFailed,
    ClientAuthFailed,
}

#[derive(Clone, PartialEq)]
struct Header {
    flags: u16,
    suite: u16,
    kx: Option<[u8; KX_PUB_LEN]>,
}

const HEADER_FLAG_REPLY: u16 = 1u16 << 15;
const HEADER_FLAG_CLIENT_AUTH: u16 = 1u16 << 14;

impl Header {
    fn size() -> usize {
        4 + KX_PUB_LEN
    }

    fn build(cs: Ciphersuite, is_reply: bool, has_client_auth: bool) -> Header {
        Header {
            flags: (if is_reply { HEADER_FLAG_REPLY } else { 0u16 })
                | (if has_client_auth {
                    HEADER_FLAG_CLIENT_AUTH
                } else {
                    0u16
                }),
            suite: cs as u16,
            kx: None,
        }
    }

    fn read<'a>(input: &'a [u8]) -> Result<(Header, &'a [u8]), Error> {
        if input.len() >= Header::size() {
            Ok((
                Header {
                    flags: BigEndian::read_u16(&input[..2]),
                    suite: BigEndian::read_u16(&input[2..]),
                    kx: Some(input[4..4 + KX_PUB_LEN].try_into().unwrap()),
                },
                &input[4 + KX_PUB_LEN..],
            ))
        } else {
            Err(Error::Truncated)
        }
    }

    fn write(&self, output: &mut [u8]) {
        assert!(output.len() >= Header::size());
        BigEndian::write_u16(&mut output[..2], self.flags);
        BigEndian::write_u16(&mut output[2..], self.suite);
        output[4..4 + KX_PUB_LEN].clone_from_slice(&self.kx.unwrap());
    }

    fn to_bytes(&self) -> [u8; 36] {
        let mut r = [0u8; 36];
        self.write(&mut r);
        r
    }

    fn to_bytes_for_aad(&self) -> [u8; 4] {
        let mut r = [0u8; 4];
        r.clone_from_slice(&self.to_bytes()[..4]);
        r
    }

    fn for_reply(&self) -> Self {
        let mut r = self.clone();
        assert!(!self.is_a_reply());
        r.flags |= HEADER_FLAG_REPLY;
        r
    }

    fn is_ciphersuite(&self, cs: Ciphersuite) -> bool {
        self.suite == (cs as u16)
    }

    fn has_client_auth(&self) -> bool {
        self.flags & HEADER_FLAG_CLIENT_AUTH != 0
    }

    fn is_a_reply(&self) -> bool {
        self.flags & HEADER_FLAG_REPLY != 0
    }

    fn set_kx(&mut self, kx: &[u8; KX_PUB_LEN]) {
        self.kx = Some(kx.clone());
    }

    fn kx(&self) -> &[u8; KX_PUB_LEN] {
        self.kx.as_ref().unwrap()
    }
}

pub struct Client {
    suite: Ciphersuite,
    client_auth: Option<(curve25519::PublicKey, curve25519::PublicKey)>,
    server: curve25519::PublicKey,
}

pub struct ClientReplyHandler {
    expected_header: Header,
    keyblock: KeyBlock,
}

impl ClientReplyHandler {
    pub fn decrypt_reply<'a>(self, input: &[u8], output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let (header, body) = Header::read(input)?;

        if !header.is_a_reply() {
            return Err(Error::UnexpectedResponse);
        }

        if header != self.expected_header {
            return Err(Error::UnexpectedHeader);
        }

        let cipher_len = body.len() - AEAD_TAG_LEN;
        output[..cipher_len].clone_from_slice(&body[..cipher_len]);
        let tag = &body[cipher_len..];

        let aesgcm = aes_gcm::Aes128Gcm::new(self.keyblock.aes().into());
        aesgcm
            .decrypt_in_place_detached(
                self.keyblock.server_nonce().into(),
                &header.to_bytes_for_aad(),
                &mut output[..cipher_len],
                tag.into(),
            )
            .map_err(|_| Error::DecryptFailed)?;

        Ok(&output[..cipher_len])
    }
}

pub struct KeyBlock([u8; 16], [u8; 12], [u8; 12]);

impl KeyBlock {
    fn aes(&self) -> &[u8] {
        &self.0[..]
    }

    fn client_nonce(&self) -> &[u8] {
        &self.1[..]
    }

    fn server_nonce(&self) -> &[u8] {
        &self.2[..]
    }
}

fn kdf(dh_param: &[u8], shared_secret: &curve25519::PublicKey) -> KeyBlock {
    let mut kb = KeyBlock([0u8; 16], [0u8; 12], [0u8; 12]);

    let mut h = Sha256::new();
    h.update(dh_param);
    h.update(shared_secret.0);
    let hash_bytes = &h.finalize();
    kb.0.clone_from_slice(&hash_bytes[..16]);
    kb.1[..8].clone_from_slice(&hash_bytes[16..24]);
    kb.1[8..].clone_from_slice(b"RQST");
    kb.2[..8].clone_from_slice(&hash_bytes[24..32]);
    kb.2[8..].clone_from_slice(b"RPLY");

    kb
}

fn x25519_generate() -> (curve25519::PublicKey, curve25519::SecretKey) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let secret = curve25519::SecretKey(curve25519::secretkey(&seed).0);
    let public = secret.get_public();
    (public, secret)
}

fn x25519_agree(d: &curve25519::SecretKey, q: &curve25519::PublicKey) -> curve25519::PublicKey {
    let mut z = curve25519::PublicKey([0u8; 32]);
    d.exchange(q, &mut z.0);
    z
}

impl Client {
    pub fn unauthenticated(server: &[u8; KX_PUB_LEN]) -> Client {
        Client {
            suite: Ciphersuite::X25519_AESGCM128,
            client_auth: None,
            server: curve25519::PublicKey(*server),
        }
    }

    pub fn generate(server: &[u8; KX_PUB_LEN]) -> Client {
        let (public, secret) = x25519_generate();
        let server_pub = curve25519::PublicKey(*server);
        let client_server_kx = x25519_agree(&secret, &server_pub);

        Client {
            suite: Ciphersuite::X25519_AESGCM128,
            client_auth: Some((public, client_server_kx)),
            server: curve25519::PublicKey(*server),
        }
    }

    pub fn public_key(&self) -> Option<[u8; KX_PUB_LEN]> {
        if let Some((public, _)) = &self.client_auth {
            Some(public.0)
        } else {
            None
        }   
    }

    fn packet_size(&self, message_len: usize) -> usize {
        let client_auth_proof_size = if let Some(_) = &self.client_auth {
            KX_PUB_LEN + KX_PRIV_LEN
        } else {
            0
        };

        let aead_tag_size = 16;

        Header::size()
            .saturating_add(client_auth_proof_size)
            .saturating_add(message_len)
            .saturating_add(aead_tag_size)
    }

    pub fn encrypt_request<'a>(
        &self,
        message: &[u8],
        output: &'a mut [u8],
    ) -> Result<(&'a [u8], ClientReplyHandler), Error> {
        let space_required = self.packet_size(message.len());
        if space_required > output.len() {
            return Err(Error::InsufficientBuffer(space_required));
        }

        let mut hdr = Header::build(self.suite, false, self.client_auth.is_some());
        let mut offset = Header::size();
        let start_message = offset;

        let shared_secret = if let Some((client_public, client_server_kx)) = &self.client_auth {
            let (_, ppk) = x25519_generate();

            let exchange_dh = x25519_agree(&ppk, client_public);
            let shared_secret = x25519_agree(&ppk, client_server_kx);

            output[offset..offset + KX_PUB_LEN].clone_from_slice(&client_public.0);
            offset += KX_PUB_LEN;

            output[offset..offset + KX_PRIV_LEN].clone_from_slice(&ppk.0);
            offset += KX_PRIV_LEN;

            hdr.set_kx(&exchange_dh.0);

            shared_secret
        } else {
            let (public, secret) = x25519_generate();
            let shared_secret = x25519_agree(&secret, &self.server);

            hdr.set_kx(&public.0);

            shared_secret
        };

        hdr.write(output);

        output[offset..offset + message.len()].clone_from_slice(message);
        let mut end_offset = offset + message.len();

        let keyblock = kdf(hdr.kx(), &shared_secret);

        let aesgcm = Aes128Gcm::new(keyblock.aes().into());
        let tag = aesgcm
            .encrypt_in_place_detached(
                keyblock.client_nonce().into(),
                &hdr.to_bytes_for_aad(),
                &mut output[start_message..end_offset],
            )
            .expect("encryption failed");

        output[end_offset..end_offset + tag.len()].clone_from_slice(&tag);
        end_offset += tag.len();

        Ok((
            &output[..end_offset],
            ClientReplyHandler {
                expected_header: hdr.for_reply(),
                keyblock: keyblock,
            },
        ))
    }
}

pub struct ServerReceivedRequest<'msg> {
    pub message: &'msg [u8],
    pub client_public: Option<[u8; KX_PUB_LEN]>,
}

pub struct ServerReplier {
    reply_header: Header,
    reply_keyblock: KeyBlock,
}

impl ServerReplier {
    pub fn encrypt_reply<'a>(
        self,
        message: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let offset = Header::size();
        self.reply_header.write(output);

        output[offset..offset + message.len()].clone_from_slice(message);
        let mut end_offset = offset + message.len();

        let aesgcm = Aes128Gcm::new(self.reply_keyblock.aes().into());
        let tag = aesgcm
            .encrypt_in_place_detached(
                self.reply_keyblock.server_nonce().into(),
                &self.reply_header.to_bytes_for_aad(),
                &mut output[offset..end_offset],
            )
            .expect("encryption failed");

        output[end_offset..end_offset + tag.len()].clone_from_slice(&tag);
        end_offset += tag.len();

        Ok(&output[..end_offset])
    }
}

pub struct Server {
    suite: Ciphersuite,
    secret: curve25519::SecretKey,
    public: curve25519::PublicKey,
}

impl Server {
    pub fn generate() -> Server {
        let (public, secret) = x25519_generate();

        Server {
            suite: Ciphersuite::X25519_AESGCM128,
            public: public,
            secret: secret,
        }
    }

    pub fn import(private_key: &[u8; KX_PRIV_LEN]) -> Server {
        let secret = curve25519::SecretKey(curve25519::secretkey(private_key).0);
        let public = secret.get_public();

        Server {
            suite: Ciphersuite::X25519_AESGCM128,
            public: public,
            secret: secret,
        }
    }

    pub fn public_key(&self) -> [u8; KX_PUB_LEN] {
        self.public.0
    }

    pub fn private_key(&self) -> [u8; KX_PRIV_LEN] {
        self.secret.0
    }

    pub fn decrypt_request<'msg>(
        &self,
        ciphertext: &[u8],
        output: &'msg mut [u8],
    ) -> Result<(ServerReceivedRequest<'msg>, ServerReplier), Error> {
        let (hdr, body) = Header::read(ciphertext)?;

        if !hdr.is_ciphersuite(self.suite) {
            return Err(Error::UnexpectedCiphersuite);
        }

        if hdr.is_a_reply() {
            return Err(Error::UnexpectedResponse);
        }

        let shared_secret = x25519_agree(&self.secret, &curve25519::PublicKey(*hdr.kx()));

        let keyblock = kdf(hdr.kx(), &shared_secret);

        if body.len() > output.len() {
            return Err(Error::InsufficientBuffer(body.len()));
        }

        let cipher_len = body.len() - AEAD_TAG_LEN;
        output[..cipher_len].clone_from_slice(&body[..cipher_len]);
        let tag = &body[cipher_len..];

        let aesgcm = Aes128Gcm::new(keyblock.aes().into());
        aesgcm
            .decrypt_in_place_detached(
                keyblock.client_nonce().into(),
                &hdr.to_bytes_for_aad(),
                &mut output[..cipher_len],
                tag.into(),
            )
            .map_err(|_| Error::DecryptFailed)?;

        let (result, client_public) = if hdr.has_client_auth() {
            let proof_size = KX_PUB_LEN + KX_PRIV_LEN;

            if cipher_len < proof_size {
                return Err(Error::Truncated);
            }

            let proof = &output[..proof_size];

            let client_public: [u8; KX_PUB_LEN] = proof[..KX_PUB_LEN].try_into().unwrap();
            let client_public = curve25519::PublicKey(client_public);

            let client_temp_priv: [u8; KX_PRIV_LEN] = proof[KX_PUB_LEN..].try_into().unwrap();
            let client_temp_priv = curve25519::secretkey(&client_temp_priv);
            let result = x25519_agree(&client_temp_priv, &client_public);

            if !bool::from(hdr.kx().ct_eq(&result.0)) {
                return Err(Error::ClientAuthFailed);
            }

            (&output[proof_size..cipher_len], Some(client_public.0))
        } else {
            (&output[..cipher_len], None)
        };

        Ok((
            ServerReceivedRequest {
                message: result,
                client_public,
            },
            ServerReplier {
                reply_header: hdr.for_reply(),
                reply_keyblock: keyblock,
            },
        ))
    }
}
