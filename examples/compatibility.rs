use std::io;

use pssst::{Client, ClientReplyHandler, Server};

extern crate hex;
use rand_core::{OsRng, RngCore};

const KX_PUB_LEN: usize = 32;

fn get_msg() -> (String, Option<Vec<u8>>) {
    let mut line = String::new();

    io::stdin()
        .read_line(&mut line)
        .expect("Failed to read input line");

    let parts: Vec<&str> = line.trim().splitn(2, ":").collect();

    let tag = String::from(parts[0]);

    match parts.get(1) {
        Some(tail) => {
            let decoded = hex::decode(tail).expect("Bad hex in input");
            (tag, Some(decoded))
        }
        None => (tag, None),
    }
}

fn emit_msg<T: AsRef<[u8]>>(tag: &str, value: T) {
    let hex_value = hex::encode(value);
    println!("{}:{}", tag, hex_value);
}

fn main() {
    let server = Server::generate();
    let server_pub_bytes = server.public_key();

    emit_msg("SERVER_KEY", server_pub_bytes);

    let mut plaintext = [0u8; 64];
    let mut reverse_plaintext = [0u8; 64];
    OsRng.fill_bytes(&mut plaintext);
    for i in 0..plaintext.len() {
        reverse_plaintext[plaintext.len() - 1 - i] = plaintext[i];
    }

    let mut remote_plaintext: Vec<u8> = Vec::new();
    let mut remote_client_key: Vec<u8> = Vec::new();

    emit_msg("PLAINTEXT", &plaintext[..]);

    let mut client_noauth_handler: Option<ClientReplyHandler> = None;
    let mut client_auth_handler: Option<ClientReplyHandler> = None;

    let mut replies = 0;
    let mut remote_done = false;

    while !remote_done && replies < 2 {
        let (tag, optv) = get_msg();

        if tag == "SERVER_KEY" {
            let value = optv.expect("Server key message had no key!");
            let mut server_key_bytes: [u8; KX_PUB_LEN] = [0; KX_PUB_LEN];

            server_key_bytes.copy_from_slice(&value[..KX_PUB_LEN]);

            let client_noauth_raw = Client::unauthenticated(&server_key_bytes);
            let client_auth_raw = Client::generate(&server_key_bytes);
            let client_key = client_auth_raw
                .public_key()
                .expect("Authenticated client had no pubic key");
            emit_msg("CLIENT_KEY", client_key);

            {
                let mut buffer = [0u8; 256];
                let (packet, handler) = client_noauth_raw
                    .encrypt_request(&plaintext, &mut buffer)
                    .expect("Failed to encrypt request");
                emit_msg("REQUEST", packet);
                client_noauth_handler = Some(handler);
            }

            {
                let mut buffer = [0u8; 256];
                let (packet, handler) = client_auth_raw
                    .encrypt_request(&plaintext, &mut buffer)
                    .expect("Failed to encrypt request");
                emit_msg("REQUEST_AUTH", packet);
                client_auth_handler = Some(handler);
            }
        } else if tag == "PLAINTEXT" {
            remote_plaintext = optv.expect("Plaintext message had no text!");
        } else if tag == "CLIENT_KEY" {
            remote_client_key = optv.expect("Client key message had no key!");
        } else if tag == "REQUEST" {
            let mut buffer = [0u8; 256];
            let value = optv.expect("Request message had no body!");
            let (request_info, replier) = server
                .decrypt_request(&value[..], &mut buffer)
                .expect("Request failed to unpack");
            if request_info.message != &remote_plaintext[..] {
                panic!("Request message was not expected plaintext");
            }

            assert_eq!(request_info.client_public, None);

            let mut reply_buffer = [0u8; 256];
            let message_length = request_info.message.len();

            for i in 0..message_length {
                reply_buffer[message_length - 1 - i] = remote_plaintext[i];
            }

            let reply_packet = replier
                .encrypt_reply(&reply_buffer[..message_length], &mut buffer)
                .expect("Failed to encrypt reply");
            emit_msg("REPLY", &reply_packet);
        } else if tag == "REQUEST_AUTH" {
            let mut buffer = [0u8; 256];
            let value = optv.expect("Auth request message had no body!");
            let (request_info, replier) = server
                .decrypt_request(&value[..], &mut buffer)
                .expect("Request failed to unpack");
            if request_info.message != &remote_plaintext[..] {
                panic!("Request message was not expected plaintext");
            }

            assert_eq!(
                request_info
                    .client_public
                    .expect("Authenticated request had no client key"),
                &remote_client_key[..]
            );

            let mut reply_buffer = [0u8; 256];
            let message_length = request_info.message.len();

            for i in 0..message_length {
                reply_buffer[message_length - 1 - i] = remote_plaintext[i];
            }

            let reply_packet = replier
                .encrypt_reply(&reply_buffer[..message_length], &mut buffer)
                .expect("Failed to encrypt reply");
            emit_msg("REPLY_AUTH", &reply_packet);
        } else if tag == "REPLY" {
            let mut buffer = [0u8; 256];
            let value = optv.expect("Reply message had no body!");
            let handler = client_noauth_handler.expect("Client handler not yet set");
            let reply_msg = handler
                .decrypt_reply(&value[..], &mut buffer)
                .expect("Unable to decrypt reply");
            assert_eq!(reply_msg, &reverse_plaintext[..]);
            client_noauth_handler = None;
            replies += 1;
            if replies == 2 {
                emit_msg("DONE", b"");
            }
        } else if tag == "REPLY_AUTH" {
            let mut buffer = [0u8; 256];
            let value = optv.expect("Reply message had no body!");
            let handler = client_auth_handler.expect("Client handler not yet set");
            let reply_msg = handler
                .decrypt_reply(&value[..], &mut buffer)
                .expect("Unable to decrypt reply");
            assert_eq!(reply_msg, &reverse_plaintext[..]);
            client_auth_handler = None;
            replies += 1;
            if replies == 2 {
                emit_msg("DONE", b"");
            }
        } else if tag == "DONE" {
            remote_done = true;
        } else {
            panic!("Unknown tag: '{}'", tag);
        }
    }
}
