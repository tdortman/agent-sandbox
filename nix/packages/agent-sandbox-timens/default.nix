# Out-of-tree kernel module, built per kernel with
# `config.boot.kernelPackages.callPackage <this file> { }`. The defaults let
# the flake's package output build it for the newest kernel.
{
  lib,
  stdenv,
  pkgs,
  kernel ? pkgs.linuxPackages_latest.kernel,
  kernelModuleMakeFlags ? pkgs.linuxPackages_latest.kernelModuleMakeFlags,
  ...
}:

stdenv.mkDerivation {
  inherit (kernel) version;
  pname = "agent-sandbox-timens";
  src = ./kernel-module;
  nativeBuildInputs = kernel.moduleBuildDependencies;

  makeFlags = kernelModuleMakeFlags ++ [
    "KDIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "INSTALL_MOD_PATH=${placeholder "out"}"
  ];

  hardeningDisable = [
    "pic"
    "format"
  ];

  installTargets = [ "modules_install" ];

  meta = {
    description = "Kernel module that rewinds a frozen time namespace's monotonic and boottime offsets";
    license = lib.licenses.gpl2Only;
    platforms = lib.platforms.linux;
    broken = kernel.kernelOlder "6.18";
  };
}
