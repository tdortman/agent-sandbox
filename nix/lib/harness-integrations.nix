{
  adapter = {
    activation = {
      ignored = [
        "cwd"
        "projectId"
        "runtimeRoot"
        "path"
        "gitRoot"
      ];

      selector = "logical-identity";
    };

    binding = {
      agent = "BindingHandle";
      operation = "ClaimHandle";
      process = "pidfd";
    };

    launcher = {
      authentication = "launcher-authenticated";
      inheritedDescriptorsOnly = true;
      opensConnection = true;
      workspacePolicyLogic = false;
    };

    lifecycle = {
      attach = [
        "foreground"
        "background"
        "pty"
      ];

      attachOnce = true;
      cgroupKeepsClaims = true;
      disconnectBackstop = true;

      release = [
        "close"
        "archive"
        "delete"
        "activation_loss"
        "restart"
      ];

      unsubscribeReleases = false;
    };

    logicalIdentityOnly = true;

    pidfd = {
      childMustBeStopped = true;
      failure = "kill-and-fail-spawn";
      request = "attach_process";
      resumeAfterAttach = true;
      sendCount = 1;
    };

    registration = "register_context_adapter";

    threads = {
      activationRequired = true;
      crossWorkspaceOverride = "authenticated";
      forkRequiresCanonicalWorkspace = true;
      turnInherits = true;
    };

    unmatched = "Unattributed";
  };

  child = {
    adapterFdEnv = "AGENT_SANDBOX_CONTEXT_ADAPTER_FD";
    executable = "agent-sandbox-child";
    inheritedAdapterDescriptorOnly = true;
    readyFdEnv = "AGENT_SANDBOX_CHILD_READY_FD";
    stopSignal = "SIGSTOP";
  };

  executables = {
    contextAdapter = "agent-sandbox-context-adapter";
    dbusBridge = "agent-sandbox-dbus-proxy";
    proxy = "agent-sandbox-proxy";
    stoppedChild = "agent-sandbox-child";
  };

  codex = {
    appServer = {
      electronAsarPatch = false;
      protocol = "newline-delimited-json-rpc";
      sharedSocket = false;
      transport = "stdio-jsonl";
      upstreamHook = "below-app-server";
    };

    desktop = {
      version = "26.825.51511";
      cliPathEnv = "CODEX_CLI_PATH";
      electronAsarPatch = false;
      nativeWrapper = true;
      packagePath = "pool/main/c/chatgpt/chatgpt_26.825.51511";
      packagingSourceCommit = "241435e57b27da16e1a4381dabeb9c63876dfab2";
      sourceCommit = "e021215ca0743dd1403bb4c76765e4316d9eea4a";
    };

    nonAppServerArgsForwardedUnchanged = true;

    runtime = {
      version = "0.151.0-alpha.7.2";
      binarySha256 = "d32a5e9f6201f8e20849ff4b52e559920b43c7937dce8051bd9fb3d4a0bef3f1";
      sourceCommit = "f70e26c29ccb731e22d1104de550b1b9594d7070";
      surveyCommit = "94cbbddafc1776d5e377bca1b05932c697e82238";
    };
  };

  dsh = {
    version = "0.1.1-rc.2";
    activation = "picker-only";
    browserAuthBootstrap = "profile-browser-auth";
    gitCommit = "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e";
    profile = "agent-sandbox";

    providers = [
      "wrap_tools_execute"
      "llm_stream"
    ];

    rawPathActivation = false;
    sourceUrl = "https://github.com/deepseek-ai/deepseek-harness";
    subprocessProvider = "agent-sandbox-child";
  };

  protocolMajor = 1;
}
