fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to locate protoc");
    // SAFETY: build scripts run single-process for this crate and setting PROTOC is required by tonic-prost-build.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let manifest_path = std::path::Path::new(&manifest_dir);
    let vendored_dir = manifest_path.join("proto-vendor").join("aegis");
    let vendored_proto = vendored_dir.join("smcp_gateway.proto");
    let sibling_dir = manifest_path.join("..").join("aegis-proto").join("proto");
    let sibling_proto = sibling_dir.join("smcp_gateway.proto");

    let (proto_dir, proto_file) = if sibling_proto.exists() {
        (sibling_dir, sibling_proto)
    } else if vendored_proto.exists() {
        (vendored_dir, vendored_proto)
    } else {
        panic!("smcp_gateway.proto not found in proto-vendor/aegis or ../aegis-proto/proto");
    };

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(
            &[proto_file.to_str().expect("proto path is not valid UTF-8")],
            &[proto_dir.to_str().expect("include dir is not valid UTF-8")],
        )
        .expect("failed to compile smcp_gateway.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());
}
