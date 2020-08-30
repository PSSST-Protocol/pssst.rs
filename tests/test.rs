#[test]
fn test_vector_1() {
    let server_priv = b"\x00\x87\x99H\x8e\xb2\x12>\x1d\xa2\xe4\x8e\xe06Z\x04\x0c\xb8uV\xcay0\xa9\x89\x11\x18\xa3\x10\xca\x93h";
    let request = b"\x00\x00\x00\x01\xbb\x1f\x0c\xa9\x1c{\x06\xc4\xf27 \x97\x83uq\xc0\xaa\xea.\tH\xe2\xefw\x8b\xa8\x01\xc1\x05\xef4U?\x89\x1e\xf7\x16\xbb=\xd0+\x90\xf7\'H\xfd\x9d\xbd\x15\xdc\xf7\x9c=\x9b\xae3!\xa1\x9b5\t\xd5\xb0/s\xa0J\xc2\xd2\xf9";
    let message = b"This is a test message";

    let mut plain_buffer = [0u8; 64];

    let server = pssst::Server::import(server_priv);
    let (request, _) = server.decrypt_request(request, &mut plain_buffer).unwrap();

    assert_eq!(request.message, message);
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
