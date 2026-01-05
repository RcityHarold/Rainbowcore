//! Performance Benchmarks for L0 Signing Operations
//!
//! Benchmarks:
//! - BLS key generation
//! - BLS signing
//! - BLS verification
//! - Signature aggregation
//! - Threshold signature creation
//! - DKG operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use l0_signer::bls::{
    aggregate_signatures, create_threshold_signature, verify_threshold_signature,
    BlsSecretKey, BlsThresholdSigner, ThresholdSignatureShare,
};
use l0_signer::crypto::L0SigningKey;
use l0_signer::dkg::{split_secret, reconstruct_secret};

/// Benchmark BLS key generation
fn bench_bls_key_generation(c: &mut Criterion) {
    c.bench_function("bls_key_generation", |b| {
        b.iter(|| {
            black_box(BlsSecretKey::generate())
        })
    });
}

/// Benchmark Ed25519 key generation
fn bench_ed25519_key_generation(c: &mut Criterion) {
    c.bench_function("ed25519_key_generation", |b| {
        b.iter(|| {
            black_box(L0SigningKey::generate())
        })
    });
}

/// Benchmark BLS signing
fn bench_bls_signing(c: &mut Criterion) {
    let sk = BlsSecretKey::generate();
    let message = b"L0 batch snapshot: epoch=1, batch=42";

    c.bench_function("bls_sign", |b| {
        b.iter(|| {
            black_box(sk.sign(black_box(message)))
        })
    });
}

/// Benchmark BLS verification
fn bench_bls_verification(c: &mut Criterion) {
    let sk = BlsSecretKey::generate();
    let pk = sk.public_key();
    let message = b"L0 batch snapshot: epoch=1, batch=42";
    let signature = sk.sign(message);

    c.bench_function("bls_verify", |b| {
        b.iter(|| {
            black_box(pk.verify(black_box(message), black_box(&signature)))
        })
    });
}

/// Benchmark Ed25519 signing
fn bench_ed25519_signing(c: &mut Criterion) {
    let sk = L0SigningKey::generate();
    let message = b"L0 batch snapshot: epoch=1, batch=42";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            black_box(sk.sign_batch(black_box(message)))
        })
    });
}

/// Benchmark signature aggregation with varying signer counts
fn bench_signature_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_aggregation");

    for count in [3, 5, 7, 9].iter() {
        let signers: Vec<BlsThresholdSigner> = (1..=*count)
            .map(|i| BlsThresholdSigner::generate(i, 9, 5))
            .collect();

        let message = b"L0 batch snapshot";
        let shares: Vec<ThresholdSignatureShare> = signers
            .iter()
            .map(|s| s.sign(message))
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &shares,
            |b, shares| {
                b.iter(|| {
                    black_box(aggregate_signatures(black_box(shares)))
                })
            },
        );
    }

    group.finish();
}

/// Benchmark threshold signature creation (5/9)
fn bench_threshold_signature_5_of_9(c: &mut Criterion) {
    let signers: Vec<BlsThresholdSigner> = (1..=9)
        .map(|i| BlsThresholdSigner::new_5_of_9(BlsSecretKey::generate(), i))
        .collect();

    let message = b"L0 batch snapshot: epoch=1, batch=42, root=abc123";
    let shares: Vec<ThresholdSignatureShare> = signers[..5]
        .iter()
        .map(|s| s.sign(message))
        .collect();

    c.bench_function("threshold_signature_5_of_9", |b| {
        b.iter(|| {
            black_box(create_threshold_signature(
                black_box(&shares),
                black_box(5),
                black_box(9),
            ))
        })
    });
}

/// Benchmark threshold signature verification
fn bench_threshold_verification(c: &mut Criterion) {
    let signers: Vec<BlsThresholdSigner> = (1..=9)
        .map(|i| BlsThresholdSigner::new_5_of_9(BlsSecretKey::generate(), i))
        .collect();

    let message = b"L0 batch snapshot: epoch=1, batch=42, root=abc123";
    let shares: Vec<ThresholdSignatureShare> = signers[..5]
        .iter()
        .map(|s| s.sign(message))
        .collect();

    let agg_sig = create_threshold_signature(&shares, 5, 9).unwrap();

    c.bench_function("threshold_verify_5_of_9", |b| {
        b.iter(|| {
            black_box(verify_threshold_signature(
                black_box(message),
                black_box(&agg_sig),
            ))
        })
    });
}

/// Benchmark DKG share splitting
fn bench_dkg_share_split(c: &mut Criterion) {
    let mut secret = [0u8; 32];
    secret[0] = 42;
    secret[1] = 123;

    c.bench_function("dkg_share_split_5_of_9", |b| {
        b.iter(|| {
            black_box(split_secret(
                black_box(&secret),
                black_box(9),
                black_box(5),
            ))
        })
    });
}

/// Benchmark DKG share reconstruction
fn bench_dkg_share_reconstruct(c: &mut Criterion) {
    let mut secret = [0u8; 32];
    secret[0] = 42;
    secret[1] = 123;

    let shares = split_secret(&secret, 9, 5).unwrap();

    c.bench_function("dkg_share_reconstruct_5_of_9", |b| {
        b.iter(|| {
            black_box(reconstruct_secret(
                black_box(&shares[..5]),
                black_box(5),
            ))
        })
    });
}

/// Benchmark full signing workflow (sign + aggregate + verify)
fn bench_full_signing_workflow(c: &mut Criterion) {
    let signers: Vec<BlsThresholdSigner> = (1..=9)
        .map(|i| BlsThresholdSigner::new_5_of_9(BlsSecretKey::generate(), i))
        .collect();

    let message = b"L0 batch snapshot: epoch=1, batch=42, root=abc123";

    c.bench_function("full_5_of_9_workflow", |b| {
        b.iter(|| {
            // Sign (5 signers)
            let shares: Vec<ThresholdSignatureShare> = signers[..5]
                .iter()
                .map(|s| s.sign(message))
                .collect();

            // Aggregate
            let agg_sig = create_threshold_signature(&shares, 5, 9).unwrap();

            // Verify
            black_box(verify_threshold_signature(message, &agg_sig))
        })
    });
}

/// Benchmark message sizes
fn bench_varying_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_size_impact");

    let sk = BlsSecretKey::generate();

    for size in [32, 256, 1024, 4096, 16384].iter() {
        let message: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &message,
            |b, msg| {
                b.iter(|| {
                    black_box(sk.sign(black_box(msg)))
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_bls_key_generation,
    bench_ed25519_key_generation,
    bench_bls_signing,
    bench_bls_verification,
    bench_ed25519_signing,
    bench_signature_aggregation,
    bench_threshold_signature_5_of_9,
    bench_threshold_verification,
    bench_dkg_share_split,
    bench_dkg_share_reconstruct,
    bench_full_signing_workflow,
    bench_varying_message_sizes,
);

criterion_main!(benches);
