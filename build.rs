#[cfg(feature = "protobuf")]
use std::path::PathBuf;

#[cfg(feature = "protobuf")]
fn build_protos() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let proto_dir = cargo_dir.join("protos");

    let mut builder = tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Deserialize, serde::Serialize)]");

    for field in vec!["start", "end", "timestamp"] {
        builder = builder.field_attribute(field, "#[serde(default, deserialize_with = \"crate::serde_helpers::deserialize_maybe_timestamp\", serialize_with = \"crate::serde_helpers::serialize_maybe_timestamp\", skip_serializing_if = \"Option::is_none\")]");
    }

    //compile suricata proto
    let suricata_proto_path = proto_dir.join("suricata_eve.proto");

    println!(
        "cargo:rerun-if-changed={}",
        suricata_proto_path
            .to_str()
            .expect("Failed to convert to string")
    );

    builder.compile(&[suricata_proto_path], &[proto_dir])?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "protobuf")]
    build_protos()?;

    Ok(())
}
