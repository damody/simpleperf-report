use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

pub const LAUNCHER_BAT: &str = "run_html.bat";
pub const REPORT_EXE: &str = "simpleperf_report.exe";

pub fn write_report_launcher(output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create '{}'", output_dir.display()))?;
    copy_report_exe(output_dir)?;
    fs::write(output_dir.join(LAUNCHER_BAT), launcher_script()).with_context(|| {
        format!(
            "Failed to write '{}'",
            output_dir.join(LAUNCHER_BAT).display()
        )
    })
}

fn copy_report_exe(output_dir: &Path) -> Result<()> {
    let current_exe = std::env::current_exe().context("Failed to resolve current executable")?;
    let target = output_dir.join(REPORT_EXE);
    if current_exe != target {
        fs::copy(&current_exe, &target).with_context(|| {
            format!(
                "Failed to copy '{}' to '{}'",
                current_exe.display(),
                target.display()
            )
        })?;
    }
    Ok(())
}

fn launcher_script() -> String {
    r#"@echo off
setlocal
cd /d "%~dp0"
set "EXE=%~dp0simpleperf_report.exe"
set "DB=%~dp0SourceLine.sqlite"
set "HTML=%~dp0SourceLine.html"

if not exist "%EXE%" (
  echo Missing "%EXE%"
  pause
  exit /b 1
)
if not exist "%DB%" (
  echo Missing "%DB%"
  pause
  exit /b 1
)
if not exist "%HTML%" (
  echo Missing "%HTML%"
  pause
  exit /b 1
)

for /f %%P in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$l.Start();$p=$l.LocalEndpoint.Port;$l.Stop();$p"') do set "PORT=%%P"
if "%PORT%"=="" set "PORT=9600"

start "SourceLine backend" /min "%EXE%" source --httpd --db "%DB%" --http-port %PORT% --listen-ip 127.0.0.1
powershell -NoProfile -ExecutionPolicy Bypass -Command "$url='http://127.0.0.1:%PORT%/'; for ($i=0; $i -lt 60; $i++) { try { Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 1 | Out-Null; Start-Process $url; exit 0 } catch { Start-Sleep -Milliseconds 250 } }; Write-Error 'SourceLine backend did not become ready'; exit 1"
"#
    .replace('\n', "\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_script_starts_bundled_backend_and_passes_api_url() {
        let script = launcher_script();

        assert!(script.contains("simpleperf_report.exe"));
        assert!(script.contains("SourceLine.sqlite"));
        assert!(script.contains("SourceLine.html"));
        assert!(script.contains("source --httpd --db"));
        assert!(script.contains("--listen-ip 127.0.0.1"));
        assert!(script.contains("Invoke-WebRequest -UseBasicParsing"));
        assert!(script.contains("Start-Process $url"));
        assert!(script.contains("set \"PORT=9600\""));
    }

    #[test]
    fn write_report_launcher_copies_exe_and_writes_batch() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let output_dir = root.join("target/source_profile_tests/report_launcher");
        let _ = fs::remove_dir_all(&output_dir);

        write_report_launcher(&output_dir).unwrap();

        assert!(output_dir.join(LAUNCHER_BAT).is_file());
        assert!(output_dir.join(REPORT_EXE).is_file());
    }
}
