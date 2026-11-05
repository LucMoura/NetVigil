//! End-to-end CLI tests for authorization enforcement.
//!
//! These tests execute the compiled binary with local configuration fixtures
//! and perform no network access.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

/// Mirrors `config::MAX_CONFIG_BYTES`; integration tests cannot import the
/// binary crate's private items.
const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// Mirrors `config::MAX_SCOPE_RULES`.
const MAX_SCOPE_RULES: usize = 4096;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn config_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(&path).expect("create target temp directory");
    path.push(format!(
        "netvigil-cli-test-{}-{}.toml",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    path
}

#[cfg(unix)]
fn secure_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set fixture permissions");
}

#[cfg(not(unix))]
fn secure_permissions(_path: &Path) {}

fn write_config(contents: &str) -> PathBuf {
    let path = config_path();
    fs::write(&path, contents).expect("write configuration fixture");
    secure_permissions(&path);
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_netvigil"))
        .args(args)
        .output()
        .expect("execute netvigil binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn authorized_target_reaches_placeholder() {
    let config = write_config("[scope]\ntargets = [\"192.0.2.10\"]\n");
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);
    let _ = fs::remove_file(&config);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("Scanning is not implemented yet"));
    assert!(stderr(&output).is_empty());
}

#[test]
fn unauthorized_target_is_blocked_before_scanning() {
    let config = write_config("[scope]\ntargets = [\"192.0.2.10\"]\n");
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.11",
    ]);
    let _ = fs::remove_file(&config);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("not authorized by the configured scope"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}

#[test]
fn missing_configuration_fails_closed() {
    let config = config_path();
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("failed to read configuration file"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}

#[test]
fn invalid_configuration_fails_closed() {
    let config = write_config("[scope]\ntargets = [\n");
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);
    let _ = fs::remove_file(&config);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("invalid configuration file"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}

#[test]
fn empty_scope_blocks_every_target() {
    let config = write_config("[scope]\ntargets = []\n");
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);
    let _ = fs::remove_file(&config);

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not authorized"));
    assert!(stdout(&output).is_empty());
}

#[test]
fn missing_config_option_fails_closed() {
    let output = run(&["scan", "192.0.2.10"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no configuration file selected"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}

#[test]
fn directory_configuration_fails_closed() {
    let config = config_path();
    fs::create_dir(&config).expect("create directory fixture");
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);
    let _ = fs::remove_dir(&config);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("is not a regular file"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}

#[test]
fn oversized_configuration_fails_closed() {
    let config = config_path();
    fs::write(&config, vec![b'\n'; MAX_CONFIG_BYTES + 1]).expect("write oversized fixture");
    secure_permissions(&config);
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);
    let _ = fs::remove_file(&config);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("exceeds the maximum size"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}

#[test]
fn excessive_rule_count_fails_closed() {
    let mut contents = String::from("[scope]\ntargets = [\n");
    for _ in 0..=MAX_SCOPE_RULES {
        contents.push_str("  \"192.0.2.1\",\n");
    }
    contents.push_str("]\n");

    let config = write_config(&contents);
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);
    let _ = fs::remove_file(&config);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("too many scope rules"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}

#[test]
fn hostile_toml_content_is_not_reproduced() {
    let config = write_config("[scope]\ntargets = [\n  \"\u{1b}]0;owned\u{7}\",\n");
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);
    let _ = fs::remove_file(&config);

    let error = stderr(&output);
    assert_eq!(output.status.code(), Some(1));
    assert!(!error.contains('\u{1b}'), "leaked ESC: {error:?}");
    assert!(!error.contains('\u{7}'), "leaked BEL: {error:?}");
    assert!(stdout(&output).is_empty());
}

#[cfg(unix)]
#[test]
fn control_characters_in_config_path_are_escaped() {
    let mut path = config_path();
    let mut name = path.file_name().expect("fixture name").to_os_string();
    name.push("\u{1b}]0;owned\u{7}");
    path.set_file_name(name);

    let output = run(&[
        "--config",
        path.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);

    let error = stderr(&output);
    assert_eq!(output.status.code(), Some(1));
    assert!(!error.contains('\u{1b}'), "leaked ESC: {error:?}");
    assert!(!error.contains('\u{7}'), "leaked BEL: {error:?}");
    assert!(error.contains("\\u{1b}"), "missing escape: {error:?}");
}

#[cfg(unix)]
#[test]
fn group_or_world_writable_configuration_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let config = write_config("[scope]\ntargets = []\n");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o666))
        .expect("set insecure permissions");
    let output = run(&[
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);
    let _ = fs::remove_file(&config);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("insecure permissions"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}

#[cfg(unix)]
#[test]
fn symbolic_link_configuration_is_rejected() {
    use std::os::unix::fs::symlink;

    let target = write_config("[scope]\ntargets = []\n");
    let link = config_path();
    symlink(&target, &link).expect("create symlink fixture");

    let output = run(&[
        "--config",
        link.to_str().expect("UTF-8 fixture path"),
        "scan",
        "192.0.2.10",
    ]);
    let _ = fs::remove_file(&link);
    let _ = fs::remove_file(&target);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("symbolic link"),
        "stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}
