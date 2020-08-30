#[test]
fn test_vector_unauth() {
    let server_priv = b"\x00\x87\x99H\x8e\xb2\x12>\x1d\xa2\xe4\x8e\xe06Z\x04\x0c\xb8uV\xcay0\xa9\x89\x11\x18\xa3\x10\xca\x93h";
    let request = b"\x00\x00\x00\x01\xbb\x1f\x0c\xa9\x1c{\x06\xc4\xf27 \x97\x83uq\xc0\xaa\xea.\tH\xe2\xefw\x8b\xa8\x01\xc1\x05\xef4U?\x89\x1e\xf7\x16\xbb=\xd0+\x90\xf7\'H\xfd\x9d\xbd\x15\xdc\xf7\x9c=\x9b\xae3!\xa1\x9b5\t\xd5\xb0/s\xa0J\xc2\xd2\xf9";
    let message = b"This is a test message";

    let mut plain_buffer = [0u8; 128];

    let server = pssst::Server::import(server_priv);
    let (request, _) = server.decrypt_request(request, &mut plain_buffer).unwrap();

    assert_eq!(request.message, message);
}

#[test]
fn test_vector_auth() {
    let server_priv = b"\x60\x09\xe9\x77\xc8\xeb\xda\xbe\xaa\xa7\x87\xc2\xfc\x2f\x72\x75\xe8\x99\x1b\x6e\xdf\x0f\xac\x65\xe6\xc0\x0c\x1b\x26\xf0\x07\x48";
    let request = b"\x40\x00\x00\x01\xe9\x25\x66\x4b\x27\xe3\x3a\x5e\x8a\xad\x69\x0a\x71\xd9\x8f\x9c\x30\xed\xff\xb1\xb6\x90\xf2\xa0\xeb\x30\xe9\x57\x04\xae\x04\x35\x64\xfa\x1f\x16\x8d\x58\x5f\x0d\x29\x5a\x64\x00\xfc\x48\xac\xd4\x9e\x80\x31\xcc\x02\xb3\x84\xb8\xf1\x7e\x67\x01\x8a\x77\x65\x07\x82\x02\x16\x1d\xf6\x98\x57\xdf\x4f\x75\xe0\x6a\xc6\xfe\x4b\x19\x6a\xb2\xff\x71\xe8\x7a\x48\x63\xdf\x3b\x84\x14\xbc\x1c\xc9\x76\x9e\x39\x1a\x18\x70\xa1\x2b\xe8\x1f\xcf\xd2\x6e\x38\x20\x11\xff\x1f\x6f\x63\xea\x1f\x22\x92\x5e\x60\x7c\x78\xaa\xf0\xb0\x9a\xc9\x02\x41\x19\x39\xf3\x33";
    let message = b"This is a test message";
    let expected_pubkey = b"\xc9\x87\x25\x0f\x4a\xca\x11\x1b\x5b\xab\xf6\x17\xeb\x87\xef\x64\x48\x31\xb1\x23\xf9\x98\x8a\x26\x79\xd4\x95\xb4\x78\x15\x5b\x6f";

    let mut plain_buffer = [0u8; 128];

    let server = pssst::Server::import(server_priv);
    let (request, _) = server.decrypt_request(request, &mut plain_buffer).unwrap();
    assert_eq!(request.message, message);
    assert_eq!(&request.client_public.unwrap(), expected_pubkey);
}

#[test]
fn smoketest_unauthenticated() {
    let server = pssst::Server::generate();
    let client = pssst::Client::unauthenticated(&server.public_key());

    let mut buffer = [0u8; 256];
    let (client_request, client_reply_handler) =
        client.encrypt_request(b"hello world", &mut buffer).unwrap();
    println!("priv: {:?}", server.private_key());
    println!("cipher: {:?}", client_request);

    let mut plain_buffer = [0u8; 256];
    let (server_request, replier) = server
        .decrypt_request(client_request, &mut plain_buffer)
        .unwrap();
    assert_eq!(server_request.message, b"hello world");
    println!("plain: {:?}", server_request.message);

    let mut reply_buffer = [0u8; 256];
    let reply = replier.encrypt_reply(b"foobar", &mut reply_buffer).unwrap();

    let mut plain_buffer = [0u8; 256];
    let reply_plain = client_reply_handler
        .decrypt_reply(reply, &mut plain_buffer)
        .unwrap();
    assert_eq!(reply_plain, b"foobar");
}

#[test]
fn smoketest_authenticated() {
    let server = pssst::Server::generate();
    let client = pssst::Client::generate(&server.public_key());

    let mut buffer = [0u8; 256];
    let (client_request, client_reply_handler) =
        client.encrypt_request(b"hello world", &mut buffer).unwrap();
    println!("priv: {:?}", server.private_key());
    println!("cipher: {:?}", client_request);

    let mut plain_buffer = [0u8; 256];
    let (server_request, replier) = server
        .decrypt_request(client_request, &mut plain_buffer)
        .unwrap();
    assert_eq!(server_request.message, b"hello world");
    println!("plain: {:?}", server_request.message);

    let mut reply_buffer = [0u8; 256];
    let reply = replier.encrypt_reply(b"foobar", &mut reply_buffer).unwrap();

    let mut plain_buffer = [0u8; 256];
    let reply_plain = client_reply_handler
        .decrypt_reply(reply, &mut plain_buffer)
        .unwrap();
    assert_eq!(reply_plain, b"foobar");
}
