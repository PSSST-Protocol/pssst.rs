use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use pssst::{Server, Client};

pub fn server_benchmark(c: &mut Criterion) {
    let server = Server::generate();
    let client = Client::unauthenticated(&server.public_key());

    let mut group = c.benchmark_group("server unauth recv");
    group.throughput(Throughput::Elements(1));

    let mut buffer = [0u8; 128];
    let (packet, _) = client.encrypt_request(b"hello world", &mut buffer)
        .unwrap();

    group.bench_function("server unauth recv", |b| b.iter(|| {
        let mut input_buffer = [0u8; 128];
        server.decrypt_request(packet, &mut input_buffer).unwrap();
    }));
}

criterion_group!(benches, server_benchmark);
criterion_main!(benches);
