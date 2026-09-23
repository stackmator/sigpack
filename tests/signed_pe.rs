//! Real-world round-trip against a genuine Authenticode-signed PE.
//!
//! Point `SIGPACK_TEST_PE` at a PE that carries an *embedded* signature
//! (`SignatureType -eq 'Authenticode'`), then run `cargo test`:
//!
//! ```console
//! PS> $env:SIGPACK_TEST_PE = "C:\Windows\System32\appverif.exe"
//! PS> cargo test
//! ```
//!
//! Without the variable the test is skipped so `cargo test` stays green on any
//! machine. Verify the modified copy with
//! `Get-AuthenticodeSignature <file>` — it should still report `Valid`.

#[test]
fn add_and_list_on_a_signed_pe() {
    let Ok(path) = std::env::var("SIGPACK_TEST_PE") else {
        eprintln!("SIGPACK_TEST_PE is not set; skipping real-PE round-trip");
        return;
    };

    let image = std::fs::read(&path).expect("read test PE");
    let blob = b"sigpack: integration test blob";

    let packed = sigpack::add_blob(&image, blob).expect("add_blob");
    let blobs = sigpack::list_blobs(&packed).expect("list_blobs");
    assert!(
        blobs.contains(&blob.to_vec()),
        "the blob should be readable after embedding"
    );

    // The result must still be a parseable PE carrying a PKCS#7 signature.
    let pe = sigpack::PeFile::parse(packed).expect("packed image parses");
    assert!(!pe.first_signature().expect("signature present").is_empty());
}

#[test]
fn cli_extract_writes_blobs_verbatim() {
    let Ok(path) = std::env::var("SIGPACK_TEST_PE") else {
        eprintln!("SIGPACK_TEST_PE is not set; skipping CLI extraction test");
        return;
    };

    let image = std::fs::read(&path).expect("read test PE");
    let blob: Vec<u8> = (0..=255).collect();
    let packed = sigpack::add_blob(&image, &blob).expect("add_blob");

    let dir = std::env::temp_dir().join("sigpack-cli-extract-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let packed_path = dir.join("packed.exe");
    std::fs::write(&packed_path, &packed).expect("write packed image");

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_sigpack"))
        .args([
            "list",
            packed_path.to_str().unwrap(),
            "--extract",
            dir.to_str().unwrap(),
        ])
        .status()
        .expect("run sigpack");
    assert!(status.success(), "sigpack list --extract failed");

    let extracted: Vec<Vec<u8>> = std::fs::read_dir(&dir)
        .expect("read temp dir")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "blob"))
        .map(|entry| std::fs::read(entry.path()).expect("read blob file"))
        .collect();

    assert!(
        extracted.contains(&blob),
        "the original blob bytes should be written verbatim"
    );
}
