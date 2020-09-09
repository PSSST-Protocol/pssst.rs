#[test]
fn test_vector_unauth() {
    let server_priv = b"\x00\x87\x99H\x8e\xb2\x12>\x1d\xa2\xe4\x8e\xe06Z\x04\x0c\xb8uV\xcay0\xa9\x89\x11\x18\xa3\x10\xca\x93h";
    let request = b"\x00\x00\x00\x01\xbf\xfd: \xa8\x1a1b\xdf\xec\x1b\x0b\xfdR\xf8\xcd\xfd\xd7\xb2q'\xcd&\x9d?\xafp\xbb\x1f\xdd\xde\x06\xdc\xb9\x89\xcc\xac\xd9>\x08\xde\x8bF\xcf\xc6%-a[\xbd\x1d\x04\x94q\x98\x9dC\xcd\x99\xed\xd4\x00n\x9f\x18\x04\xf6\xae\xdf\xe0";

    let message = b"This is a test message";

    let mut plain_buffer = [0u8; 128];

    let server = pssst::Server::import(server_priv);
    let (request, _) = server.decrypt_request(request, &mut plain_buffer).unwrap();

    assert_eq!(request.message, message);
}

#[test]
fn test_vector_auth() {
    let server_priv = b"\x60\x09\xe9\x77\xc8\xeb\xda\xbe\xaa\xa7\x87\xc2\xfc\x2f\x72\x75\xe8\x99\x1b\x6e\xdf\x0f\xac\x65\xe6\xc0\x0c\x1b\x26\xf0\x07\x48";
    let request = b"@\x00\x00\x017`&P\xc7oI\xe7\x05qg\x0b\x15D!L\xb5\xbf\x8d\xf2_\xf6\xba\xe5\x1b\xf2\x99\xf5\x04\xfb\x08Z\x8d\xe6Z\x1c,\x10\xf8\xc2\xfc\xbc\xca\x0e\xe7ZF\xa5\x848IZ6\x94\x13&\x9b[\x80\xde\xf4~4SK\xd8L\xe5\x81\xa7(e\xb4\x8a:]\xf9\x1aU\xff\x1e.\x8c\x04\xa2V\x8c9\xd2\x11\xa4\x99zv\xa4p\xfb\x03V\xe5\x01ALrU'c\xc5\x7f\xddA\xf8\x84\x97\xf8\xf9\x91\xd2\x03p6wH?U\x15f\\y\xcf\xb1\xcc\xb5\x12";
    let message = b"This is a test message";
    let expected_pubkey = b"\xff\xce\xdf\x08\xf2\xc9]\xa6%W\x0f\xd9\xfd\xcf\xa6\x8c.\xc2\x8b\xc9\x19\x06\x979_h#\xab9\xb7\xfa@";

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
