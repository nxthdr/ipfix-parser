use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use ipfix_parser::{parse_messages, Decoder};
use std::hint::black_box;

/// Benchmark parsing the real IPFIX capture (Templates and Data Records)
fn bench_parse_real_messages(c: &mut Criterion) {
    let data = std::fs::read("tests/data/ipfix.bin").expect("Failed to read tests/data/ipfix.bin");

    let mut group = c.benchmark_group("parse_messages");
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("real_ipfix_data", |b| {
        b.iter(|| {
            let result = parse_messages(black_box(&data));
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark decoding with a warm Template cache, the steady state of a
/// collector (Templates are only sent once per refresh interval)
fn bench_decode_warm_cache(c: &mut Criterion) {
    let data = std::fs::read("tests/data/ipfix.bin").expect("Failed to read tests/data/ipfix.bin");

    let mut decoder = Decoder::new();
    decoder.decode_all(&data).expect("Failed to decode");

    let mut group = c.benchmark_group("decode_warm_cache");
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("real_ipfix_data", |b| {
        b.iter(|| {
            let result = decoder.decode_all(black_box(&data));
            black_box(result)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_parse_real_messages, bench_decode_warm_cache);
criterion_main!(benches);
