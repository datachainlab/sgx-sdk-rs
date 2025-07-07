use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// Default file names and target name
const TARGET_NAME: &str = "x86_64-unknown-unknown-sgx";
const TARGET_JSON_FILE: &str = "x86_64-unknown-unknown-sgx.json";
const ENCLAVE_CONFIG_FILE: &str = "Enclave.config.xml";
const ENCLAVE_EDL_FILE: &str = "Enclave.edl";
const ENCLAVE_PRIVATE_KEY_FILE: &str = "Enclave_private.pem";
const ENCLAVE_LDS_FILE: &str = "Enclave.lds";
const ENCLAVE_SO_FILE: &str = "enclave.so";
const DEFAULT_ENCLAVE_NAME: &str = "enclave";
const SGX_SDK_REPO_URL: &str = "https://github.com/datachainlab/sgx-sdk-rs";

/// Get the target directory for EDL artifacts
fn get_edl_target_dir() -> PathBuf {
    // Check CARGO_TARGET_DIR first, then default to "target"
    let target_base = if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
        PathBuf::from(target_dir)
    } else {
        PathBuf::from("target")
    };

    target_base.join("edl")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Mitigation {
    #[value(name = "CVE-2020-0551-LOAD")]
    Cve20200551Load,
    #[value(name = "CVE-2020-0551-CF")]
    Cve20200551Cf,
}

impl std::fmt::Display for Mitigation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mitigation::Cve20200551Load => write!(f, "CVE-2020-0551-LOAD"),
            Mitigation::Cve20200551Cf => write!(f, "CVE-2020-0551-CF"),
        }
    }
}

#[derive(Parser)]
#[command(name = "cargo")]
#[command(bin_name = "cargo")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CargoCommand,
}

#[derive(Subcommand)]
enum CargoCommand {
    #[command(name = "sgx")]
    #[command(about = "SGX enclave development tools")]
    Sgx {
        #[command(subcommand)]
        command: SgxSubCommand,
    },
}

#[derive(Subcommand)]
enum SgxSubCommand {
    #[command(about = "Build SGX enclave shared object")]
    Build(SgxBuildArgs),
    #[command(about = "Create a new SGX enclave project with template files")]
    New(SgxNewArgs),
}

#[derive(Parser)]
struct SgxBuildArgs {
    /// Path to the enclave project directory (default: current directory)
    #[arg(short, long)]
    enclave_dir: Option<PathBuf>,

    /// Build in release mode
    #[arg(short, long)]
    release: bool,

    /// Target specification file (default: searches for x86_64-unknown-unknown-sgx.json)
    #[arg(long)]
    target: Option<PathBuf>,

    /// Output path for enclave.so (default: next to the static library)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Version script file path (default: auto-generated Enclave.lds)
    #[arg(long)]
    version_script: Option<PathBuf>,

    /// EDL file path (default: {enclave_dir}/Enclave.edl)
    #[arg(long)]
    edl: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Parser)]
struct SgxNewArgs {
    /// Path for the new enclave project (default: ./enclave)
    path: Option<PathBuf>,

    /// Enclave name (default: uses directory name)
    #[arg(short, long)]
    name: Option<String>,

    /// Force overwrite existing files
    #[arg(short, long)]
    force: bool,

    /// CVE mitigation strategy
    #[arg(long, value_enum)]
    mitigation: Option<Mitigation>,

    /// Path to sgx-sdk-rs repository (default: uses GitHub URL)
    #[arg(long)]
    sgx_sdk_path: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        CargoCommand::Sgx { command } => match command {
            SgxSubCommand::Build(args) => {
                if let Err(e) = run_sgx_build(args) {
                    eprintln!("Error: {e:#}");
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
            SgxSubCommand::New(args) => {
                if let Err(e) = run_sgx_new(args) {
                    eprintln!("Error: {e:#}");
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
        },
    }
}

fn run_sgx_build(args: SgxBuildArgs) -> Result<()> {
    let enclave_dir = args.enclave_dir.unwrap_or_else(|| PathBuf::from("."));

    // Check if we're in an enclave project
    let cargo_toml = enclave_dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        anyhow::bail!("No Cargo.toml found in {}", enclave_dir.display());
    }

    // Read Cargo.toml to get the package name
    let cargo_toml_content =
        fs::read_to_string(&cargo_toml).context("Failed to read Cargo.toml")?;
    let cargo_toml: toml::Value =
        toml::from_str(&cargo_toml_content).context("Failed to parse Cargo.toml")?;

    let package_name = cargo_toml
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .context("Failed to get package name from Cargo.toml")?;

    let lib_name = cargo_toml
        .get("lib")
        .and_then(|l| l.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or(package_name);

    // Find the target JSON file
    let target_json = if let Some(target) = args.target {
        target
    } else {
        get_sgx_target_json(&enclave_dir)?
    };

    // Build the enclave
    println!("Building enclave...");
    let profile = if args.release { "release" } else { "debug" };

    let mut cargo_build = Command::new("cargo");
    cargo_build
        .current_dir(&enclave_dir)
        .arg("build")
        .arg("--target")
        .arg(&target_json);

    if args.release {
        cargo_build.arg("--release");
    }

    if args.verbose {
        cargo_build.arg("-v");
    }

    let status = cargo_build
        .status()
        .context("Failed to execute cargo build")?;

    if !status.success() {
        anyhow::bail!("Cargo build failed");
    }

    // Find the static library
    let target_dir = enclave_dir
        .join(format!("target/{TARGET_NAME}"))
        .join(profile);
    let static_lib = target_dir.join(format!("lib{}.a", lib_name.replace('-', "_")));

    if !static_lib.exists() {
        anyhow::bail!("Static library not found: {}", static_lib.display());
    }

    // Determine output path
    let output_path = args
        .output
        .unwrap_or_else(|| target_dir.join(ENCLAVE_SO_FILE));

    // Create enclave.so
    println!("Creating {ENCLAVE_SO_FILE}...");
    create_enclave_so(
        &static_lib,
        &output_path,
        &enclave_dir,
        args.version_script,
        args.edl,
        args.verbose,
    )?;

    println!("Successfully built: {}", output_path.display());

    Ok(())
}

fn get_sgx_target_json(enclave_dir: &Path) -> Result<PathBuf> {
    // Check only in the enclave directory itself
    let target_json = enclave_dir.join(TARGET_JSON_FILE);
    if target_json.exists() {
        Ok(target_json)
    } else {
        anyhow::bail!(
            "Could not find {} in {}",
            TARGET_JSON_FILE,
            enclave_dir.display()
        )
    }
}

fn create_enclave_so(
    static_lib: &Path,
    output: &Path,
    enclave_dir: &Path,
    version_script_path: Option<PathBuf>,
    edl_path: Option<PathBuf>,
    verbose: bool,
) -> Result<()> {
    // Find or use specified EDL file
    let edl_path = if let Some(edl_path) = edl_path {
        // Use user-specified EDL file
        if !edl_path.exists() {
            anyhow::bail!("EDL file not found: {}", edl_path.display());
        }
        edl_path
    } else {
        // Default: use Enclave.edl in enclave directory
        let default_edl = enclave_dir.join(ENCLAVE_EDL_FILE);
        if !default_edl.exists() {
            anyhow::bail!("Default EDL file not found: {}", default_edl.display());
        }
        default_edl
    };
    let edl_name = edl_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid EDL filename"))?
        .to_string();

    // EDL library is now in target/edl directory
    let edl_lib_dir = get_edl_target_dir();

    // Determine version script path
    let version_script = if let Some(script_path) = version_script_path {
        // Use user-provided version script
        if !script_path.exists() {
            anyhow::bail!("Version script not found: {}", script_path.display());
        }
        Some(script_path)
    } else {
        // First check if Enclave.lds exists in the enclave directory
        let enclave_dir_script = enclave_dir.join(ENCLAVE_LDS_FILE);
        if enclave_dir_script.exists() {
            Some(enclave_dir_script)
        } else {
            // Generate default version script if needed
            let default_script = output
                .parent()
                .unwrap_or(Path::new("."))
                .join(ENCLAVE_LDS_FILE);
            if !default_script.exists() {
                create_version_script(&default_script)?;
            }
            Some(default_script)
        }
    };

    if verbose {
        println!("Building {ENCLAVE_SO_FILE} with sgx-build...");
        println!("Static library: {}", static_lib.display());
        println!("Output: {}", output.display());
        println!("EDL name: {edl_name}");
        if let Some(ref script) = version_script {
            println!("Version script: {}", script.display());
        }
    }

    // Use sgx-build to create enclave.so
    let edl_lib_name = format!("{edl_name}_t");

    sgx_build::SgxBuilder::new()
        .build_enclave_so(
            static_lib,
            output,
            version_script.as_deref(),
            &edl_lib_name,
            &edl_lib_dir,
        )
        .map_err(|e| anyhow::anyhow!("Failed to build {}: {}", ENCLAVE_SO_FILE, e))?;

    Ok(())
}

fn create_version_script(path: &Path) -> Result<()> {
    let content = r#"enclave.so
{
    global:
        g_global_data_sim;
        g_global_data;
        enclave_entry;
        g_peak_heap_used;
    local:
        *;
};
"#;

    fs::write(path, content).context("Failed to write version script")?;
    Ok(())
}

fn run_sgx_new(args: SgxNewArgs) -> Result<()> {
    let project_dir = args
        .path
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ENCLAVE_NAME));

    // Create directory if it doesn't exist
    if !project_dir.exists() {
        fs::create_dir_all(&project_dir).context("Failed to create project directory")?;
    }

    // Determine enclave name
    let enclave_name = args.name.unwrap_or_else(|| {
        project_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(DEFAULT_ENCLAVE_NAME)
            .to_string()
    });

    // Use mitigation option directly (now it's an enum)
    let mitigation = args.mitigation.map(|m| m.to_string());

    // Calculate relative path from project directory to current directory
    let sgx_sdk_path = if let Some(sdk_path) = args.sgx_sdk_path {
        // Get current directory
        let current_dir = env::current_dir().context("Failed to get current directory")?;
        // Make the SDK path absolute based on current directory
        let absolute_sdk_path = current_dir.join(&sdk_path);
        // Calculate relative path from project directory to SDK path
        let absolute_project_dir = current_dir.join(&project_dir);
        pathdiff::diff_paths(&absolute_sdk_path, &absolute_project_dir)
    } else {
        None
    };

    // Create template files
    create_cargo_toml(&project_dir, &enclave_name, args.force, sgx_sdk_path)?;
    create_src_lib_rs(&project_dir, args.force)?;
    create_build_rs(&project_dir, args.force, mitigation.as_deref())?;
    create_enclave_config(&project_dir, &enclave_name, args.force)?;
    create_enclave_edl(&project_dir, &enclave_name, args.force)?;
    create_enclave_private_key(&project_dir, args.force)?;
    create_enclave_lds(&project_dir, args.force)?;
    create_target_json(&project_dir, args.force, mitigation.as_deref())?;
    create_cargo_config(&project_dir, args.force)?;
    create_gitignore(&project_dir, args.force)?;

    println!(
        "Successfully initialized SGX enclave project at {}",
        project_dir.display()
    );
    let display_path = project_dir.display();
    println!("Created files:");
    println!("  - {display_path}/Cargo.toml");
    println!("  - {display_path}/src/lib.rs");
    println!("  - {display_path}/build.rs");
    println!("  - {display_path}/{ENCLAVE_CONFIG_FILE}");
    println!("  - {display_path}/{ENCLAVE_EDL_FILE}");
    println!("  - {display_path}/{ENCLAVE_PRIVATE_KEY_FILE} (RSA 3072-bit private key)");
    println!("  - {display_path}/{ENCLAVE_LDS_FILE}");
    println!("  - {display_path}/{TARGET_JSON_FILE}");
    println!("  - {display_path}/.cargo/config.toml");
    println!("  - {display_path}/.gitignore");

    Ok(())
}

fn create_build_rs(dir: &Path, force: bool, mitigation: Option<&str>) -> Result<()> {
    let path = dir.join("build.rs");
    if path.exists() && !force {
        println!("Skipping build.rs (already exists)");
        return Ok(());
    }

    let mitigation_env = match mitigation {
        Some("CVE-2020-0551-LOAD") => {
            "    std::env::set_var(\"MITIGATION_CVE_2020_0551\", \"LOAD\");"
        }
        Some("CVE-2020-0551-CF") => "    std::env::set_var(\"MITIGATION_CVE_2020_0551\", \"CF\");",
        _ => "",
    };

    let content = if mitigation_env.is_empty() {
        format!(
            r#"fn main() {{
    sgx_build::SgxBuilder::new()
        .build_enclave("{ENCLAVE_EDL_FILE}")
        .expect("Failed to build SGX enclave");
}}
"#
        )
    } else {
        format!(
            r#"fn main() {{
{mitigation_env}
    sgx_build::SgxBuilder::new()
        .build_enclave("{ENCLAVE_EDL_FILE}")
        .expect("Failed to build SGX enclave");
}}
"#
        )
    };

    fs::write(path, content).context("Failed to write build.rs")?;
    Ok(())
}

fn create_enclave_config(dir: &Path, _name: &str, force: bool) -> Result<()> {
    let path = dir.join(ENCLAVE_CONFIG_FILE);
    if path.exists() && !force {
        println!("Skipping {ENCLAVE_CONFIG_FILE} (already exists)");
        return Ok(());
    }

    let content = r#"<EnclaveConfiguration>
  <ProdID>0</ProdID>
  <ISVSVN>0</ISVSVN>
  <StackMaxSize>0x40000</StackMaxSize>
  <HeapMaxSize>0x100000</HeapMaxSize>
  <TCSNum>1</TCSNum>
  <TCSPolicy>1</TCSPolicy>
  <!-- Recommend changing to 1 for production -->
  <DisableDebug>0</DisableDebug>
  <MiscSelect>0</MiscSelect>
  <MiscMask>0xFFFFFFFF</MiscMask>
</EnclaveConfiguration>
"#;

    fs::write(path, content).with_context(|| format!("Failed to write {ENCLAVE_CONFIG_FILE}"))?;
    Ok(())
}

fn create_enclave_edl(dir: &Path, _name: &str, force: bool) -> Result<()> {
    let path = dir.join(ENCLAVE_EDL_FILE);
    if path.exists() && !force {
        println!("Skipping {ENCLAVE_EDL_FILE} (already exists)");
        return Ok(());
    }

    let content = r#"enclave {
    trusted {
        /* Add your trusted functions here */
        public sgx_status_t ecall_sample(
            [in, size=input_len] const char* input,
            size_t input_len,
            [out, size=output_max_len] char* output,
            size_t output_max_len,
            [out] size_t* output_len
        );
    };

    untrusted {
        /* Add your ocalls here */
    };
};
"#;

    fs::write(path, content).with_context(|| format!("Failed to write {ENCLAVE_EDL_FILE}"))?;
    Ok(())
}

fn create_enclave_private_key(dir: &Path, force: bool) -> Result<()> {
    let path = dir.join(ENCLAVE_PRIVATE_KEY_FILE);
    if path.exists() && !force {
        println!("Skipping {ENCLAVE_PRIVATE_KEY_FILE} (already exists)");
        return Ok(());
    }

    // Generate RSA 3072-bit private key using openssl command
    let output = Command::new("openssl")
        .args(["genrsa", "-out", path.to_str().unwrap(), "-3", "3072"])
        .output()
        .context(
            "Failed to execute openssl genrsa. Please ensure OpenSSL is installed and in your PATH",
        )?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to generate private key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

fn create_enclave_lds(dir: &Path, force: bool) -> Result<()> {
    let path = dir.join(ENCLAVE_LDS_FILE);
    if path.exists() && !force {
        println!("Skipping {ENCLAVE_LDS_FILE} (already exists)");
        return Ok(());
    }

    create_version_script(&path)?;
    Ok(())
}

fn create_target_json(dir: &Path, force: bool, mitigation: Option<&str>) -> Result<()> {
    let path = dir.join(TARGET_JSON_FILE);
    if path.exists() && !force {
        println!("Skipping {TARGET_JSON_FILE} (already exists)");
        return Ok(());
    }

    // Load template and replace placeholders based on mitigation option
    let template = include_str!("../x86_64-unknown-unknown-sgx.json.template");

    let (features, llvm_args) = match mitigation {
        None => {
            // No mitigation - empty llvm-args array
            ("", "[]")
        }
        Some("CVE-2020-0551-LOAD") | Some("CVE-2020-0551-CF") => {
            // Full LVI mitigation
            (
                ",+lvi-cfi,+lvi-load-hardening",
                r#"["--x86-experimental-lvi-inline-asm-hardening"]"#,
            )
        }
        _ => unreachable!("Invalid mitigation option"),
    };

    let content = template
        .replace("{{MITIGATION_FEATURES}}", features)
        .replace("{{MITIGATION_LLVM_ARGS}}", llvm_args);

    fs::write(path, content).context("Failed to write target JSON")?;
    Ok(())
}

fn create_cargo_config(dir: &Path, force: bool) -> Result<()> {
    let cargo_dir = dir.join(".cargo");
    fs::create_dir_all(&cargo_dir).context("Failed to create .cargo directory")?;

    let path = cargo_dir.join("config.toml");
    if path.exists() && !force {
        println!("Skipping .cargo/config.toml (already exists)");
        return Ok(());
    }

    let content = format!(
        r#"[build]
target = "{TARGET_NAME}"

[unstable]
build-std = ["core", "alloc"]
"#
    );

    fs::write(path, content).context("Failed to write .cargo/config.toml")?;
    Ok(())
}

fn create_cargo_toml(
    dir: &Path,
    enclave_name: &str,
    force: bool,
    sgx_sdk_path: Option<PathBuf>,
) -> Result<()> {
    let path = dir.join("Cargo.toml");
    if path.exists() && !force {
        println!("Skipping Cargo.toml (already exists)");
        return Ok(());
    }

    let dependencies = if let Some(ref sdk_path) = sgx_sdk_path {
        let sdk_path_str = sdk_path.to_string_lossy();
        format!(
            r#"sgx-ert = {{ path = "{sdk_path_str}/sgx-ert" }}
sgx-types = {{ path = "{sdk_path_str}/sgx-types", default-features = false, features = [
  "tstdc",
  "trts",
  "tcrypto",
] }}"#
        )
    } else {
        format!(
            r#"sgx-ert = {{ git = "{SGX_SDK_REPO_URL}", branch = "main" }}
sgx-types = {{ git = "{SGX_SDK_REPO_URL}", branch = "main", default-features = false, features = [
  "tstdc",
  "trts",
  "tcrypto",
] }}"#
        )
        .to_string()
    };

    let build_dependencies = if let Some(ref sdk_path) = sgx_sdk_path {
        let sdk_path_str = sdk_path.to_string_lossy();
        format!(r#"sgx-build = {{ path = "{sdk_path_str}/sgx-build" }}"#)
    } else {
        format!(r#"sgx-build = {{ git = "{SGX_SDK_REPO_URL}", branch = "main" }}"#)
    };

    // Use sanitized enclave name for lib name (replace hyphens with underscores)
    let lib_name = enclave_name.replace('-', "_");

    let content = format!(
        r#"[package]
name = "{enclave_name}"
version = "0.1.0"
authors = ["Your Name <you@example.com>"]
edition = "2021"

[lib]
name = "{lib_name}"
crate-type = ["staticlib"]

[features]
default = []

[dependencies]
{dependencies}

[build-dependencies]
{build_dependencies}
"#
    );

    fs::write(path, content).context("Failed to write Cargo.toml")?;
    Ok(())
}

fn create_src_lib_rs(dir: &Path, force: bool) -> Result<()> {
    // Create src directory
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).context("Failed to create src directory")?;

    let path = src_dir.join("lib.rs");
    if path.exists() && !force {
        println!("Skipping src/lib.rs (already exists)");
        return Ok(());
    }

    let content = r#"#![no_std]
extern crate alloc;
extern crate sgx_ert;

use alloc::format;
use alloc::slice;
use alloc::string::String;
use sgx_types::*;

/// Sample ecall function that corresponds to the EDL definition
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ecall_sample(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_max_len: usize,
    output_len: *mut usize,
) -> sgx_status_t {
    // Validate output_len pointer
    if output_len.is_null() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    // Convert input to string
    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };
    let input_string = match String::from_utf8(input_slice.to_vec()) {
        Ok(s) => s,
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    // Process the input (example: echo back with prefix)
    let result = format!("Hello from enclave: {}", input_string);
    let result_bytes = result.as_bytes();

    // Check if output buffer is large enough
    if result_bytes.len() > output_max_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    // Copy result to output buffer
    let output_slice = unsafe { slice::from_raw_parts_mut(output, output_max_len) };
    output_slice[..result_bytes.len()].copy_from_slice(result_bytes);

    // Set the actual output length
    unsafe {
        *output_len = result_bytes.len();
    }

    sgx_status_t::SGX_SUCCESS
}
"#;

    fs::write(path, content).context("Failed to write src/lib.rs")?;
    Ok(())
}

fn create_gitignore(dir: &Path, force: bool) -> Result<()> {
    let path = dir.join(".gitignore");
    if path.exists() && !force {
        println!("Skipping .gitignore (already exists)");
        return Ok(());
    }

    let content = r#"# Build directory
target/
"#;

    fs::write(path, content).context("Failed to write .gitignore")?;
    Ok(())
}
