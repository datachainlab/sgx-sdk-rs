//! Build utilities for SGX enclaves
//!
//! This crate provides common build functionality for SGX enclaves,
//! handling EDL processing, compilation flags, and linker configuration.

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use std::str::FromStr;

/// SGX execution mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SgxMode {
    /// Hardware mode (requires SGX-enabled CPU)
    #[default]
    Hardware,
    /// Simulation mode (for development without SGX hardware)
    Simulation,
}

impl fmt::Display for SgxMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SgxMode::Hardware => write!(f, "HW"),
            SgxMode::Simulation => write!(f, "SW"),
        }
    }
}

impl FromStr for SgxMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "HW" => Ok(SgxMode::Hardware),
            "SW" | "SIM" => Ok(SgxMode::Simulation),
            _ => Err(format!("Invalid SGX mode: {s}")),
        }
    }
}

/// CVE-2020-0551 (Load Value Injection) mitigation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cve20200551Mitigation {
    /// LOAD: Insert LFENCE after all load operations (highest security, more overhead)
    Load,
    /// CF: Insert LFENCE only before control flow changes (balanced security/performance)
    ControlFlow,
    /// Disable mitigation (not recommended for production)
    #[default]
    None,
}

impl fmt::Display for Cve20200551Mitigation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cve20200551Mitigation::Load => write!(f, "LOAD"),
            Cve20200551Mitigation::ControlFlow => write!(f, "CF"),
            Cve20200551Mitigation::None => write!(f, "NONE"),
        }
    }
}

impl FromStr for Cve20200551Mitigation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "LOAD" => Ok(Cve20200551Mitigation::Load),
            "CF" => Ok(Cve20200551Mitigation::ControlFlow),
            "NONE" => Ok(Cve20200551Mitigation::None),
            _ => Err(format!("Invalid CVE-2020-0551 mitigation: {s}")),
        }
    }
}

/// Output information from EDL processing
pub struct EdlOutput {
    pub c_file: PathBuf,
    pub h_file: PathBuf,
    pub lib_name: String,
}

/// Builder for SGX applications (both enclave and app components)
pub struct SgxBuilder {
    sgx_sdk: PathBuf,
    sgx_mode: SgxMode,
    sgx_arch: String,
    debug: bool,
    mitigation_cve_2020_0551: Cve20200551Mitigation,
    gcc_version: Option<(u32, u32, u32)>,
}

impl SgxBuilder {
    /// Get the target directory for EDL artifacts
    fn get_edl_target_dir() -> PathBuf {
        // First, try CARGO_TARGET_DIR which is explicitly set
        if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
            return PathBuf::from(target_dir).join("edl");
        }

        // Otherwise, require OUT_DIR to be set (should always be set in build.rs context)
        let out_dir = env::var("OUT_DIR")
            .expect("OUT_DIR not set. This function should only be called from build.rs");

        let out_path = PathBuf::from(out_dir);

        // Find the target directory by looking for a directory named "target"
        // while traversing up the directory tree
        let mut current_dir = out_path.as_path();
        loop {
            if let Some(file_name) = current_dir.file_name() {
                if file_name == "target" {
                    return current_dir.join("edl");
                }
            }

            match current_dir.parent() {
                Some(parent) => current_dir = parent,
                None => panic!(
                    "Could not find 'target' directory in OUT_DIR path: {}",
                    out_path.display()
                ),
            }
        }
    }

    /// Create a new EnclaveBuilder with default settings from environment
    pub fn new() -> Self {
        let sgx_sdk = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
        let sgx_mode = env::var("SGX_MODE")
            .ok()
            .and_then(|s| SgxMode::from_str(&s).ok())
            .unwrap_or_default();
        let sgx_arch = env::var("SGX_ARCH").unwrap_or_else(|_| {
            if cfg!(target_pointer_width = "32") {
                "x86".to_string()
            } else {
                "x64".to_string()
            }
        });
        let debug =
            env::var("SGX_DEBUG").is_ok() || env::var("DEBUG").is_ok() || cfg!(debug_assertions);
        let mitigation_cve_2020_0551 = match env::var("MITIGATION_CVE_2020_0551")
            .or_else(|_| env::var("MITIGATION-CVE-2020-0551"))
        {
            Ok(val) if val.is_empty() => Cve20200551Mitigation::default(),
            Ok(val) => Cve20200551Mitigation::from_str(&val)
                .unwrap_or_else(|e| panic!("Invalid MITIGATION_CVE_2020_0551 value: {e}")),
            Err(_) => Cve20200551Mitigation::default(),
        };

        let gcc_version = Self::detect_gcc_version();

        Self {
            sgx_sdk: PathBuf::from(sgx_sdk),
            sgx_mode,
            sgx_arch,
            debug,
            mitigation_cve_2020_0551,
            gcc_version,
        }
    }

    /// Detect GCC version
    fn detect_gcc_version() -> Option<(u32, u32, u32)> {
        let output = Command::new("gcc").arg("--version").output().ok()?;

        let version_str = str::from_utf8(&output.stdout).ok()?;
        let first_line = version_str.lines().next()?;

        // Parse version from output like "gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"
        // Look for pattern like "9.4.0"
        for word in first_line.split_whitespace() {
            let parts: Vec<&str> = word.split('.').collect();
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    let patch = if parts.len() >= 3 {
                        parts[2].parse::<u32>().unwrap_or(0)
                    } else {
                        0
                    };
                    return Some((major, minor, patch));
                }
            }
        }

        None
    }

    /// Get SDK library path based on architecture
    pub fn get_sdk_lib_path(&self) -> PathBuf {
        match self.sgx_arch.as_str() {
            "x86" => self.sgx_sdk.join("lib"),
            _ => self.sgx_sdk.join("lib64"),
        }
    }

    /// Get architecture-specific flags
    fn get_arch_flags(&self) -> &'static str {
        match self.sgx_arch.as_str() {
            "x86" => "-m32",
            _ => "-m64",
        }
    }

    /// Process EDL file and generate C code
    pub fn edl_generate(&self, edl_path: &Path, trusted: bool) -> Result<EdlOutput, String> {
        let edl_name = edl_path
            .file_stem()
            .ok_or("Invalid EDL path")?
            .to_str()
            .ok_or("Invalid EDL filename")?;

        let suffix = if trusted { "_t" } else { "_u" };
        let edger8r = self.sgx_sdk.join("bin/x64/sgx_edger8r");

        let mut cmd = Command::new(&edger8r);

        if trusted {
            cmd.arg("--trusted");
        } else {
            cmd.arg("--untrusted");
        }

        cmd.args([
            edl_path.to_str().unwrap(),
            "--search-path",
            self.sgx_sdk.join("include").to_str().unwrap(),
        ]);

        // Add additional search paths if needed
        if let Ok(sgx_edl_search_paths) = env::var("SGX_EDL_SEARCH_PATHS") {
            for path in sgx_edl_search_paths.split(':') {
                cmd.args(["--search-path", path]);
            }
        }

        // Use EDL file's directory as the search path
        let edl_dir = edl_path
            .parent()
            .ok_or("Invalid EDL path: no parent directory")?;

        // Add search path for the EDL directory
        cmd.args(["--search-path", edl_dir.to_str().unwrap()]);

        // Set output directory to target/edl
        let target_dir = Self::get_edl_target_dir();
        std::fs::create_dir_all(&target_dir)
            .map_err(|e| format!("Failed to create EDL target directory: {e}"))?;

        if trusted {
            cmd.args(["--trusted-dir", target_dir.to_str().unwrap()]);
        } else {
            cmd.args(["--untrusted-dir", target_dir.to_str().unwrap()]);
        }

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run sgx_edger8r: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "sgx_edger8r failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(EdlOutput {
            c_file: Self::get_edl_target_dir().join(format!("{edl_name}{suffix}.c")),
            h_file: Self::get_edl_target_dir().join(format!("{edl_name}{suffix}.h")),
            lib_name: format!("{edl_name}{suffix}"),
        })
    }

    /// Compile EDL-generated C file
    pub fn compile_edl(&self, c_file: &Path, enclave: bool, lib_name: &str) {
        let mut build = cc::Build::new();

        // Include the directory containing the C file (where EDL headers are)
        let c_file_dir = c_file
            .parent()
            .expect("C file should have a parent directory");

        build
            .file(c_file)
            .flag(self.get_arch_flags())
            .include(self.sgx_sdk.join("include"))
            .include(c_file_dir);

        // Common flags
        self.apply_common_flags(&mut build);

        if enclave {
            self.apply_enclave_compile_flags(&mut build);
        } else {
            self.apply_app_compile_flags(&mut build);
        }

        // Enable cargo metadata output in debug mode
        build.cargo_metadata(self.debug);

        // Set output directory to target/edl
        let target_dir = Self::get_edl_target_dir();
        std::fs::create_dir_all(&target_dir).expect("Failed to create EDL target directory");
        build.out_dir(&target_dir);

        build.compile(lib_name);
    }

    /// Apply common compiler flags based on buildenv.mk
    fn apply_common_flags(&self, build: &mut cc::Build) {
        // Stack protector based on GCC version
        // For simplicity, we'll use the stronger version
        build.flag("-fstack-protector-strong");

        // Function and data sections for better optimization
        build.flag("-ffunction-sections");
        build.flag("-fdata-sections");

        // Architecture-specific defines
        match self.sgx_arch.as_str() {
            "x86" => build.define("ITT_ARCH_IA32", None),
            _ => build.define("ITT_ARCH_IA64", None),
        };

        // Warning flags
        build
            .flag("-Wall")
            .flag("-Wextra")
            .flag("-Winit-self")
            .flag("-Wpointer-arith")
            .flag("-Wreturn-type")
            .flag("-Waddress")
            .flag("-Wsequence-point")
            .flag("-Wformat-security")
            .flag("-Wmissing-include-dirs")
            .flag("-Wfloat-equal")
            .flag("-Wundef")
            .flag("-Wshadow")
            .flag("-Wcast-align")
            .flag("-Wconversion")
            .flag("-Wredundant-decls");

        // Additional security flags
        build.flag("-Wjump-misses-init");
        build.flag("-Wstrict-prototypes");
        build.flag("-Wunsuffixed-float-constants");

        // Debug/Release specific flags
        if self.debug {
            build
                .flag("-ggdb")
                .flag("-O0")
                .flag("-g")
                .define("DEBUG", None)
                .define("UNDEBUG", None);
        } else {
            build
                .flag("-O2")
                .define("_FORTIFY_SOURCE", "2")
                .define("UDEBUG", None)
                .define("NDEBUG", None);
        }
    }

    /// Apply enclave-specific compile flags
    fn apply_enclave_compile_flags(&self, build: &mut cc::Build) {
        build
            .flag("-nostdinc")
            .flag("-fvisibility=hidden")
            .flag("-fpie")
            .flag("-ffreestanding")
            .flag("-fno-strict-overflow")
            .flag("-fno-delete-null-pointer-checks");

        // Enclave includes
        build.include(self.sgx_sdk.join("include/tlibc"));

        // No builtin functions
        build.flag("-fno-builtin-printf").flag("-fno-builtin");

        // Apply mitigation flags for enclave only
        self.apply_mitigation_flags(build);
    }

    /// Apply app-specific compile flags
    fn apply_app_compile_flags(&self, build: &mut cc::Build) {
        // App side uses standard libraries
        build.flag("-fPIC");
        // Do not apply mitigation flags for app side
    }

    /// Apply mitigation flags for CVE-2020-0551
    fn apply_mitigation_flags(&self, build: &mut cc::Build) {
        // Mitigation flags for CVE-2020-0551
        if self.sgx_mode == SgxMode::Hardware {
            match self.mitigation_cve_2020_0551 {
                Cve20200551Mitigation::Load | Cve20200551Mitigation::ControlFlow => {
                    // MITIGATION_C=1 flags
                    // MITIGATION_INDIRECT=1 flag
                    build.flag("-mindirect-branch-register");

                    // MITIGATION_RET=1 flags
                    if let Some((major, _, _)) = self.gcc_version {
                        // GCC 8+ specific flag
                        if major >= 8 {
                            build.flag("-fcf-protection=none");
                        }

                        if self.debug {
                            println!("cargo:warning=Using GCC {} mitigation flags for CVE-2020-0551 ({})", major, self.mitigation_cve_2020_0551);
                        }
                    } else if self.debug {
                        println!("cargo:warning=Could not detect GCC version, some CVE-2020-0551 mitigation flags may be missing");
                    }

                    // This flag is always added when MITIGATION_RET=1
                    build.flag("-mfunction-return=thunk-extern");

                    // MITIGATION_ASM=1 flags
                    build.flag("-fno-plt");

                    // MITIGATION_AFTERLOAD flags
                    match self.mitigation_cve_2020_0551 {
                        Cve20200551Mitigation::Load => {
                            // MITIGATION_AFTERLOAD=1
                            build.flag("-Wa,-mlfence-after-load=yes");
                            build.flag("-Wa,-mlfence-before-indirect-branch=memory");
                        }
                        Cve20200551Mitigation::ControlFlow => {
                            // MITIGATION_AFTERLOAD=0
                            build.flag("-Wa,-mlfence-before-indirect-branch=all");
                        }
                        Cve20200551Mitigation::None => unreachable!(),
                    }

                    // MITIGATION_RET=1 assembler flag
                    build.flag("-Wa,-mlfence-before-ret=shl");
                }
                Cve20200551Mitigation::None => {}
            }
        }
    }

    /// Setup linker flags for enclave
    pub fn setup_enclave_linker(&self) {
        // Common security linker flags from buildenv.mk
        println!("cargo:rustc-link-arg=-Wl,-z,relro,-z,now,-z,noexecstack");

        // Enclave-specific linker flags from buildenv.mk
        println!("cargo:rustc-link-arg=-nostdlib");
        println!("cargo:rustc-link-arg=-nodefaultlibs");
        println!("cargo:rustc-link-arg=-nostartfiles");
        println!("cargo:rustc-link-arg=-Wl,-Bstatic");
        println!("cargo:rustc-link-arg=-Wl,-Bsymbolic");
        println!("cargo:rustc-link-arg=-Wl,--no-undefined");
        println!("cargo:rustc-link-arg=-Wl,-pie,-eenclave_entry");
        println!("cargo:rustc-link-arg=-Wl,--export-dynamic");
        println!("cargo:rustc-link-arg=-Wl,--defsym,__ImageBase=0");
        println!("cargo:rustc-link-arg=-Wl,--gc-sections");

        // Architecture-specific flags
        println!("cargo:rustc-link-arg={}", self.get_arch_flags());
    }

    #[allow(clippy::needless_doctest_main)]
    /// One-liner build setup for SGX app (untrusted) builds
    ///
    /// This handles the most common case: processing an EDL file and setting up
    /// all necessary build configuration for an SGX app.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// fn main() {
    ///     sgx_build::SgxBuilder::new()
    ///         .build_app("../enclave/Enclave.edl")
    ///         .expect("Failed to build SGX app");
    /// }
    /// ```
    pub fn build_app<P: AsRef<Path>>(&self, edl_path: P) -> Result<(), String> {
        let edl_path = edl_path.as_ref();

        // Convert to absolute path if relative
        let edl_path = if edl_path.is_relative() {
            env::current_dir()
                .map_err(|e| format!("Failed to get current directory: {e}"))?
                .join(edl_path)
        } else {
            edl_path.to_path_buf()
        };

        // Process EDL file for untrusted side
        let edl_output = self.edl_generate(&edl_path, false)?;

        // Compile the generated C file
        self.compile_edl(&edl_output.c_file, false, &edl_output.lib_name);

        // Set up linker search path and library (in target/edl)
        let edl_dir = Self::get_edl_target_dir();
        println!("cargo:rustc-link-search=native={}", edl_dir.display());
        println!("cargo:rustc-link-lib=static={}", edl_output.lib_name);

        // Tell cargo to rerun if EDL changes
        println!("cargo:rerun-if-changed={}", edl_path.display());

        Ok(())
    }

    #[allow(clippy::needless_doctest_main)]
    /// One-liner build setup for SGX enclave (trusted) builds
    ///
    /// This handles the most common case: processing an EDL file and setting up
    /// all necessary build configuration for an SGX enclave.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// fn main() {
    ///     sgx_build::SgxBuilder::new()
    ///         .build_enclave("Enclave.edl")
    ///         .expect("Failed to build SGX enclave");
    /// }
    /// ```
    pub fn build_enclave<P: AsRef<Path>>(&self, edl_path: P) -> Result<(), String> {
        let edl_path = edl_path.as_ref();

        // Convert to absolute path if relative
        let edl_path = if edl_path.is_relative() {
            env::current_dir()
                .map_err(|e| format!("Failed to get current directory: {e}"))?
                .join(edl_path)
        } else {
            edl_path.to_path_buf()
        };

        // Process EDL file for trusted side
        let edl_output = self.edl_generate(&edl_path, true)?;

        // Compile the generated C file
        self.compile_edl(&edl_output.c_file, true, &edl_output.lib_name);

        // Set up linker configuration for enclave
        self.setup_enclave_linker();

        // Add search path for the generated EDL object (in target/edl)
        let edl_dir = Self::get_edl_target_dir();
        println!("cargo:rustc-link-search=native={}", edl_dir.display());

        // Link with the generated EDL object
        println!("cargo:rustc-link-lib=static={}", edl_output.lib_name);

        // Tell cargo to rerun if EDL changes
        println!("cargo:rerun-if-changed={}", edl_path.display());

        Ok(())
    }

    /// Build enclave shared object from static library
    pub fn build_enclave_so(
        &self,
        static_lib_path: &Path,
        output_path: &Path,
        version_script: Option<&Path>,
        edl_lib_name: &str,
        edl_lib_dir: &Path,
    ) -> Result<(), String> {
        let mut cc_build = cc::Build::new();

        cc_build
            .target("x86_64-unknown-linux-gnu")
            .host("x86_64-unknown-linux-gnu")
            .opt_level(if self.debug { 0 } else { 2 });

        // Enable cargo metadata output in debug mode
        cc_build.cargo_metadata(self.debug);

        let mut cmd = cc_build.get_compiler().to_command();

        // Architecture flag
        cmd.arg(self.get_arch_flags());

        // Common linker flags
        cmd.args([
            "-Wl,--no-undefined",
            "-nostdlib",
            "-nodefaultlibs",
            "-nostartfiles",
            "-Wl,-Bstatic",
            "-Wl,-Bsymbolic",
            "-Wl,--no-undefined",
            "-Wl,-pie,-eenclave_entry",
            "-Wl,--export-dynamic",
            "-Wl,--defsym,__ImageBase=0",
            "-Wl,--gc-sections",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
        ]);

        // Link the tRTS with the --whole-archive option,
        // so that the whole content of the trusted runtime library is included in the enclave.
        let trts_lib = match self.sgx_mode {
            SgxMode::Simulation => "sgx_trts_sim",
            SgxMode::Hardware => "sgx_trts",
        };
        cmd.arg(format!("-L{}", self.get_sdk_lib_path().display()));
        cmd.args([
            "-Wl,--whole-archive",
            &format!("-l{trts_lib}"),
            "-Wl,--no-whole-archive",
        ]);

        cmd.arg("-Wl,--start-group");

        // Add the static library
        cmd.arg(static_lib_path);

        // Add EDL object
        cmd.arg(format!("-L{}", edl_lib_dir.display()));
        cmd.arg(format!("-l{edl_lib_name}"));

        cmd.arg("-Wl,--end-group");

        // Version script
        if let Some(script_path) = version_script {
            if script_path.exists() {
                cmd.arg(format!("-Wl,--version-script={}", script_path.display()));
            } else {
                return Err(format!(
                    "Version script not found: {}",
                    script_path.display()
                ));
            }
        }

        // Output file
        cmd.arg("-o");
        cmd.arg(output_path);

        // Debug output
        if self.debug {
            eprintln!("Executing linker command: {cmd:?}");
        }

        // Execute the command
        let output = cmd
            .output()
            .map_err(|e| format!("Failed to execute linker: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Provide detailed error information
            let mut error_msg = String::from("Linking failed:\n");
            if !stderr.is_empty() {
                error_msg.push_str(&format!("stderr: {stderr}\n"));
            }
            if !stdout.is_empty() {
                error_msg.push_str(&format!("stdout: {stdout}\n"));
            }

            return Err(error_msg);
        }

        // Log success in debug mode
        if self.debug {
            eprintln!(
                "Successfully created enclave shared object: {}",
                output_path.display()
            );
        }

        Ok(())
    }
}

impl Default for SgxBuilder {
    fn default() -> Self {
        Self::new()
    }
}
