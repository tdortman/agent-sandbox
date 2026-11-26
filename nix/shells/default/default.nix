{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  rust = (import "${inputs.self}/nix/lib/rust-toolchain.nix") { inherit pkgs; };

  # Kernel the out-of-tree module is edited against; the VM checks boot the
  # same one.
  kmodKernelPackages = pkgs.linuxPackages_latest;
  kmodKernel = kmodKernelPackages.kernel;

  # One flag per line; some carry Kbuild syntax such as `$(space)` literally.
  kmodMakeFlags = pkgs.writeText "agent-sandbox-kmod-make-flags" (
    lib.concatLines kmodKernelPackages.kernelModuleMakeFlags
  );

  # clangd reads kernel module compile flags from a compilation database that
  # Kbuild generates. The build runs with the kernel's own make flags and
  # tools, kept off the shell's PATH so its rustc does not shadow the repo
  # toolchain. Output goes to target/, never into the module source tree.
  kmodCompileCommands = pkgs.writeShellApplication {
    name = "agent-sandbox-kmod-compile-commands";

    runtimeInputs = with pkgs; [
      gnumake
      pahole
      perl
      elfutils
      python3
      zstd
    ];

    text = ''
      root="''${1:-$PWD}"
      src="$root/nix/packages/agent-sandbox-timens/kernel-module"
      out="$root/target/agent-sandbox-timens"
      kdir=${lib.escapeShellArg "${kmodKernel.dev}/lib/modules/${kmodKernel.modDirVersion}/build"}
      mapfile -t make_flags < ${kmodMakeFlags}

      [[ -f "$src/Kbuild" ]] || exit 0

      stamp="$kdir"$'\n'"$src"

      if [[ -f "$out/compile_commands.json" && "$(cat "$out/.stamp" 2>/dev/null)" == "$stamp" ]] \
        && [[ -z "$(find "$src" -type f -newer "$out/compile_commands.json")" ]]; then
        exit 0
      fi

      mkdir -p "$out"
      make -s -C "$kdir" M="$src" MO="$out" "''${make_flags[@]}" modules compile_commands.json
      printf '%s\n' "$stamp" > "$out/.stamp"
    '';
  };
in
pkgs.mkShell {
  env = {
    CPATH =
      "${pkgs.qt6.qtbase.out}/include"
      + ":"
      + "${pkgs.qt6.qtbase.out}/include/QtWidgets"
      + ":"
      + "${pkgs.qt6.qtbase.out}/include/QtGui"
      + ":"
      + "${pkgs.qt6.qtbase.out}/include/QtCore"
      + ":"
      + "${pkgs.libbpf.out}/include";

    SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
  };

  nativeBuildInputs = with pkgs; [
    ast-grep
    cargo-edit
    cargo-nextest
    cmake
    curl
    kmodCompileCommands
    llvmPackages_22.clang-tools
    pkg-config
    rust.rustPlatform.bindgenHook
    rust.toolchain
  ];

  shellHook = ''
    if ! bash scripts/materialize-vendor.sh; then
      echo "ERROR: vendor/ is not materialized!" >&2
      echo "Run scripts/materialize-vendor.sh to fix this." >&2
    fi

    if ! agent-sandbox-kmod-compile-commands "$PWD"; then
      echo "WARNING: kernel module compile_commands.json was not generated; clangd will not resolve the kernel module's headers." >&2
      echo "Run agent-sandbox-kmod-compile-commands to retry." >&2
    fi
  '';
}
