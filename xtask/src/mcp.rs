//! MCP server management
//!
//! Commands for starting, installing, and managing the MCP signing server.

use anyhow::{bail, Context, Result};
use console::style;
use std::path::Path;
use std::process::Command;

/// Start the MCP server (foreground)
pub fn mcp_start() -> Result<()> {
    println!("{}", style("Starting La Propaganda MCP Server...").cyan().bold());
    println!();

    // Check if mcp-server binary exists or needs to be built
    let status = Command::new("cargo")
        .args(["run", "-p", "mcp-server", "--release"])
        .status()
        .context("Failed to start MCP server")?;

    if !status.success() {
        bail!("MCP server exited with error");
    }

    Ok(())
}

/// Check MCP server status
pub fn mcp_status() -> Result<()> {
    println!("{}", style("MCP Server Status").cyan().bold());
    println!();

    // Check if systemd service exists (Linux)
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("systemctl")
            .args(["--user", "is-active", "la-propaganda-mcp"])
            .output();

        match output {
            Ok(out) => {
                let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
                match status.as_str() {
                    "active" => {
                        println!("  systemd service: {}", style("RUNNING").green().bold());

                        // Get more details
                        let _ = Command::new("systemctl")
                            .args(["--user", "status", "la-propaganda-mcp", "--no-pager"])
                            .status();
                    }
                    "inactive" => {
                        println!("  systemd service: {}", style("STOPPED").yellow());
                        println!();
                        println!("  Start with: {}", style("systemctl --user start la-propaganda-mcp").cyan());
                    }
                    _ => {
                        println!("  systemd service: {}", style("NOT INSTALLED").dim());
                        println!();
                        println!("  Install with: {}", style("cargo run -p xtask -- mcp-install").cyan());
                    }
                }
            }
            Err(_) => {
                println!("  systemd: {}", style("not available").dim());
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Check launchd on macOS
        let plist_path = dirs::home_dir()
            .map(|h| h.join("Library/LaunchAgents/com.lapropaganda.mcp.plist"));

        if let Some(path) = plist_path {
            if path.exists() {
                let output = Command::new("launchctl")
                    .args(["list", "com.lapropaganda.mcp"])
                    .output();

                match output {
                    Ok(out) if out.status.success() => {
                        println!("  launchd service: {}", style("INSTALLED").green());
                        println!();
                        println!("  Status: launchctl list com.lapropaganda.mcp");
                    }
                    _ => {
                        println!("  launchd service: {}", style("INSTALLED but not running").yellow());
                    }
                }
            } else {
                println!("  launchd service: {}", style("NOT INSTALLED").dim());
                println!();
                println!("  Install with: {}", style("cargo run -p xtask -- mcp-install").cyan());
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Check Windows Task Scheduler
        let output = Command::new("schtasks")
            .args(["/Query", "/TN", "LaPropagandaMCP", "/FO", "LIST"])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("Running") {
                    println!("  Windows Task: {}", style("RUNNING").green().bold());
                } else {
                    println!("  Windows Task: {}", style("INSTALLED (not running)").yellow());
                }
                println!();
                println!("  Start with: {}", style("schtasks /Run /TN LaPropagandaMCP").cyan());
            }
            _ => {
                println!("  Windows Task: {}", style("NOT INSTALLED").dim());
                println!();
                println!("  Install with: {}", style("cargo run -p xtask -- mcp-install").cyan());
            }
        }
    }

    println!();
    println!("{}", style("Manual start:").yellow());
    println!("  cargo run -p xtask -- mcp-start");
    println!("  # or directly:");
    println!("  cargo run -p mcp-server --release");

    Ok(())
}

/// Install MCP server as a system service
pub fn mcp_install() -> Result<()> {
    println!("{}", style("Installing MCP Server as System Service").cyan().bold());
    println!();

    // Get the project directory
    let project_dir = std::env::current_dir()?;

    #[cfg(target_os = "linux")]
    {
        install_systemd_service(&project_dir)?;
    }

    #[cfg(target_os = "macos")]
    {
        install_launchd_service(&project_dir)?;
    }

    #[cfg(target_os = "windows")]
    {
        install_windows_task(&project_dir)?;
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        println!("{}", style("Service installation not supported on this platform.").yellow());
        println!();
        println!("Run manually with: cargo run -p mcp-server --release");
    }

    Ok(())
}

/// Uninstall MCP server system service
pub fn mcp_uninstall() -> Result<()> {
    println!("{}", style("Uninstalling MCP Server Service").cyan().bold());
    println!();

    #[cfg(target_os = "linux")]
    {
        // Stop and disable
        let _ = Command::new("systemctl")
            .args(["--user", "stop", "la-propaganda-mcp"])
            .status();
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "la-propaganda-mcp"])
            .status();

        // Remove service file
        if let Some(home) = dirs::home_dir() {
            let service_path = home.join(".config/systemd/user/la-propaganda-mcp.service");
            if service_path.exists() {
                std::fs::remove_file(&service_path)?;
                println!("{}", style("Service file removed").green());
            }
        }

        // Reload systemd
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();

        println!("{}", style("Service uninstalled successfully").green().bold());
    }

    #[cfg(target_os = "macos")]
    {
        // Unload service
        let _ = Command::new("launchctl")
            .args(["unload", "com.lapropaganda.mcp"])
            .status();

        // Remove plist
        if let Some(home) = dirs::home_dir() {
            let plist_path = home.join("Library/LaunchAgents/com.lapropaganda.mcp.plist");
            if plist_path.exists() {
                std::fs::remove_file(&plist_path)?;
                println!("{}", style("Service file removed").green());
            }
        }

        println!("{}", style("Service uninstalled successfully").green().bold());
    }

    #[cfg(target_os = "windows")]
    {
        // Delete scheduled task
        let status = Command::new("schtasks")
            .args(["/Delete", "/TN", "LaPropagandaMCP", "/F"])
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("{}", style("Scheduled task removed").green());
            }
            _ => {
                println!("{}", style("Task not found or already removed").yellow());
            }
        }

        println!("{}", style("Service uninstalled successfully").green().bold());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn install_systemd_service(project_dir: &Path) -> Result<()> {
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    let systemd_dir = home.join(".config/systemd/user");
    std::fs::create_dir_all(&systemd_dir)?;

    // Build the release binary first
    println!("Building MCP server (release)...");
    let build_status = Command::new("cargo")
        .args(["build", "-p", "mcp-server", "--release"])
        .current_dir(project_dir)
        .status()?;

    if !build_status.success() {
        bail!("Failed to build MCP server");
    }

    let binary_path = project_dir.join("target/release/mcp-server");
    if !binary_path.exists() {
        bail!("Binary not found at {:?}", binary_path);
    }

    let service_content = format!(
        r#"[Unit]
Description=La Propaganda MCP Signing Server
Documentation=https://github.com/anthropics/claude-code
After=network.target

[Service]
Type=simple
WorkingDirectory={project_dir}
ExecStart={binary_path}
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=default.target
"#,
        project_dir = project_dir.display(),
        binary_path = binary_path.display(),
    );

    let service_path = systemd_dir.join("la-propaganda-mcp.service");
    std::fs::write(&service_path, service_content)?;

    println!("{}", style("Service file created:").green());
    println!("  {}", service_path.display());
    println!();

    // Reload systemd
    Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()?;

    // Enable and start
    Command::new("systemctl")
        .args(["--user", "enable", "la-propaganda-mcp"])
        .status()?;

    Command::new("systemctl")
        .args(["--user", "start", "la-propaganda-mcp"])
        .status()?;

    println!("{}", style("Service installed and started!").green().bold());
    println!();
    println!("{}", style("Management commands:").yellow());
    println!("  systemctl --user status la-propaganda-mcp");
    println!("  systemctl --user stop la-propaganda-mcp");
    println!("  systemctl --user restart la-propaganda-mcp");
    println!("  journalctl --user -u la-propaganda-mcp -f");
    println!();
    println!("{}", style("To start on boot (requires lingering):").yellow());
    println!("  loginctl enable-linger $USER");

    Ok(())
}

#[cfg(target_os = "macos")]
fn install_launchd_service(project_dir: &Path) -> Result<()> {
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    let launch_agents = home.join("Library/LaunchAgents");
    std::fs::create_dir_all(&launch_agents)?;

    // Build the release binary first
    println!("Building MCP server (release)...");
    let build_status = Command::new("cargo")
        .args(["build", "-p", "mcp-server", "--release"])
        .current_dir(project_dir)
        .status()?;

    if !build_status.success() {
        bail!("Failed to build MCP server");
    }

    let binary_path = project_dir.join("target/release/mcp-server");
    let log_path = project_dir.join(".mcp-audit/mcp-server.log");
    let err_path = project_dir.join(".mcp-audit/mcp-server.err");

    // Ensure log directory exists
    std::fs::create_dir_all(project_dir.join(".mcp-audit"))?;

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.lapropaganda.mcp</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary_path}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{project_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_path}</string>
    <key>StandardErrorPath</key>
    <string>{err_path}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
"#,
        binary_path = binary_path.display(),
        project_dir = project_dir.display(),
        log_path = log_path.display(),
        err_path = err_path.display(),
    );

    let plist_path = launch_agents.join("com.lapropaganda.mcp.plist");
    std::fs::write(&plist_path, plist_content)?;

    println!("{}", style("Service file created:").green());
    println!("  {}", plist_path.display());
    println!();

    // Load the service
    Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap()])
        .status()?;

    println!("{}", style("Service installed and started!").green().bold());
    println!();
    println!("{}", style("Management commands:").yellow());
    println!("  launchctl list | grep lapropaganda");
    println!("  launchctl unload ~/Library/LaunchAgents/com.lapropaganda.mcp.plist");
    println!("  tail -f {}", log_path.display());

    Ok(())
}

#[cfg(target_os = "windows")]
fn install_windows_task(project_dir: &Path) -> Result<()> {
    // Build the release binary first
    println!("Building MCP server (release)...");
    let build_status = Command::new("cargo")
        .args(["build", "-p", "mcp-server", "--release"])
        .current_dir(project_dir)
        .status()?;

    if !build_status.success() {
        bail!("Failed to build MCP server");
    }

    let binary_path = project_dir.join("target/release/mcp-server.exe");
    if !binary_path.exists() {
        bail!("Binary not found at {:?}", binary_path);
    }

    // Ensure log directory exists
    let log_dir = project_dir.join(".mcp-audit");
    std::fs::create_dir_all(&log_dir)?;

    // Create XML task definition for Task Scheduler
    let task_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>La Propaganda MCP Signing Server</Description>
    <URI>\LaPropagandaMCP</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{binary_path}</Command>
      <WorkingDirectory>{project_dir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#,
        binary_path = binary_path.display(),
        project_dir = project_dir.display(),
    );

    // Write task XML to temp file
    let temp_dir = std::env::temp_dir();
    let task_xml_path = temp_dir.join("la-propaganda-mcp-task.xml");
    std::fs::write(&task_xml_path, task_xml)?;

    println!("{}", style("Task definition created").green());

    // Register the task using schtasks
    let status = Command::new("schtasks")
        .args([
            "/Create",
            "/TN", "LaPropagandaMCP",
            "/XML", task_xml_path.to_str().unwrap(),
            "/F",  // Force overwrite if exists
        ])
        .status()?;

    // Clean up temp file
    let _ = std::fs::remove_file(&task_xml_path);

    if !status.success() {
        bail!("Failed to create scheduled task. Try running as administrator.");
    }

    // Start the task immediately
    let _ = Command::new("schtasks")
        .args(["/Run", "/TN", "LaPropagandaMCP"])
        .status();

    println!("{}", style("Service installed and started!").green().bold());
    println!();
    println!("{}", style("Management commands:").yellow());
    println!("  schtasks /Query /TN LaPropagandaMCP /FO LIST");
    println!("  schtasks /Run /TN LaPropagandaMCP");
    println!("  schtasks /End /TN LaPropagandaMCP");
    println!("  schtasks /Delete /TN LaPropagandaMCP /F");
    println!();
    println!("{}", style("Logs:").yellow());
    println!("  type {}\\.mcp-audit\\mcp-server.log", project_dir.display());

    Ok(())
}
