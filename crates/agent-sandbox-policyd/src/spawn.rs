//! Auto-spawn agent-sandbox-ui via runuser when no policy UI is connected.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agent_sandbox_core::graphical_env::{graphical_session_env, tool_path};
use nix::unistd::User;

use crate::store::PolicydArgs;
use crate::wire::UiSpawnContext;

pub fn ui_spawn_env(
    args: &PolicydArgs,
    user: &User,
    uid: u32,
    home: Option<&str>,
    cwd: Option<&str>,
    project_root: Option<&str>,
    sandbox_session_id: Option<&str>,
) -> HashMap<String, String> {
    let home_dir = home.map_or_else(|| user.dir.to_string_lossy().into_owned(), str::to_string);
    let mut env = HashMap::from([
        ("HOME".into(), home_dir.clone()),
        ("USER".into(), user.name.clone()),
        ("LOGNAME".into(), user.name.clone()),
        (
            "AGENT_SANDBOX_POLICY_SOCKET".into(),
            args.socket.display().to_string(),
        ),
    ]);
    if let Some(home) = home {
        env.insert("AGENT_SANDBOX_HOME".into(), home.to_string());
    }
    if let Some(cwd) = cwd {
        env.insert("AGENT_SANDBOX_CWD".into(), cwd.to_string());
    }
    if let Some(project_root) = project_root {
        env.insert(
            "AGENT_SANDBOX_PROJECT_ROOT".into(),
            project_root.to_string(),
        );
    }
    if let Some(sandbox_session_id) = sandbox_session_id {
        env.insert(
            "AGENT_SANDBOX_SESSION_ID".into(),
            sandbox_session_id.to_string(),
        );
    }
    env.extend(graphical_session_env(uid, Some(&home_dir)));
    env.insert("AGENT_SANDBOX_UI_PREFER_GRAPHICAL".into(), "1".into());

    let profile_bin = format!("/etc/profiles/per-user/{}/bin", user.name);
    if Path::new(&profile_bin).is_dir() {
        let path = env.get("PATH").cloned().unwrap_or_default();
        env.insert("PATH".into(), format!("{profile_bin}:{path}"));
    }
    if let Some(kdialog) = tool_path("AGENT_SANDBOX_KDIALOG", "kdialog") {
        env.insert("AGENT_SANDBOX_KDIALOG".into(), kdialog.clone());
        if let Some(parent) = Path::new(&kdialog).parent() {
            let parent = parent.to_string_lossy();
            let path = env.get("PATH").cloned().unwrap_or_default();
            if !path.split(':').any(|d| d == parent.as_ref()) {
                env.insert("PATH".into(), format!("{parent}:{path}"));
            }
        }
    }
    env
}

pub fn maybe_spawn_ui<S: BuildHasher>(
    args: &PolicydArgs,
    ui_spawn_last: &mut HashMap<String, Instant, S>,
    spawn: &UiSpawnContext<'_>,
) {
    let Some(cmd) = args
        .ui_spawn_cmd
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
    else {
        return;
    };
    if spawn.gate.has_matching_ui {
        return;
    }
    let Some(uid) = spawn.uid.filter(|u| *u > 0) else {
        tracing::warn!(
            cwd = spawn.cwd.unwrap_or(""),
            project_root = spawn.project_root.unwrap_or(""),
            "cannot spawn policy UI (missing uid)"
        );
        return;
    };
    let spawn_key = format!(
        "{}:{}:{}:{}",
        uid,
        spawn.sandbox_session_id.unwrap_or(""),
        spawn.cwd.unwrap_or(""),
        spawn.project_root.unwrap_or("")
    );
    let now = Instant::now();
    if ui_spawn_last
        .get(&spawn_key)
        .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(10))
    {
        return;
    }
    ui_spawn_last.insert(spawn_key.clone(), now);

    let Ok(Some(user)) = User::from_uid(nix::unistd::Uid::from_raw(uid)) else {
        return;
    };

    let Some(runuser) = tool_path("AGENT_SANDBOX_RUNUSER", "runuser") else {
        tracing::warn!("cannot spawn policy UI (runuser not found)");
        return;
    };

    let env = ui_spawn_env(
        args,
        &user,
        uid,
        spawn.home,
        spawn.cwd,
        spawn.project_root,
        spawn.sandbox_session_id,
    );
    let ui_log_path = format!("/run/user/{uid}/agent-sandbox-ui.log");
    let stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ui_log_path)
        .map_or_else(|_| Stdio::null(), Stdio::from);

    let mut command = Command::new(&runuser);
    command
        .arg("-p")
        .arg("-u")
        .arg(&user.name)
        .arg("--")
        .arg(&cmd);
    if let Some(cwd) = spawn.cwd {
        command.arg("--cwd").arg(cwd);
    }
    if let Some(home) = spawn.home {
        command.arg("--home").arg(home);
    }
    if let Some(project_root) = spawn.project_root {
        command.arg("--project-root").arg(project_root);
    }
    command
        .envs(&env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let spawn_result = command.spawn();
    let Ok(mut child) = spawn_result else {
        if let Err(err) = spawn_result {
            tracing::warn!(uid, error = %err, "policy UI spawn failed");
        }
        return;
    };

    std::thread::sleep(Duration::from_millis(100));
    match child.try_wait() {
        Ok(Some(status)) => {
            ui_spawn_last.remove(&spawn_key);
            tracing::warn!(
                uid,
                exit_code = ?status.code(),
                log_path = %ui_log_path,
                "policy UI spawn exited early"
            );
            return;
        }
        Ok(None) => {}
        Err(err) => {
            tracing::warn!(uid, error = %err, "policy UI spawn wait failed");
            return;
        }
    }

    tracing::info!(
        uid,
        user = %user.name,
        log_path = %ui_log_path,
        "spawned policy UI"
    );

    if let Some(notify) = tool_path("AGENT_SANDBOX_NOTIFY_SEND", "notify-send") {
        let _ = Command::new(&runuser)
            .args([
                "-p",
                "-u",
                &user.name,
                "--",
                &notify,
                "agent-sandbox",
                "Network approval needed. Respond to the KDE prompt.",
            ])
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}
