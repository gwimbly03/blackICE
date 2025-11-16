{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = [
    pkgs.python3
    pkgs.poetry
    pkgs.python3Packages.cffi
    pkgs.python3Packages.charset-normalizer
    pkgs.python3Packages.cryptography
    pkgs.python3Packages.dnspython
    pkgs.python3Packages.idna
    pkgs.python3Packages.markdown-it-py
    pkgs.python3Packages.mdurl
    pkgs.python3Packages.orjson
    pkgs.python3Packages.psutil
    pkgs.python3Packages.pycparser
    pkgs.python3Packages.pygments
    pkgs.python3Packages.pyopenssl
    pkgs.python3Packages.pyyaml
    pkgs.python3Packages.readchar
    pkgs.python3Packages.requests
    pkgs.python3Packages.rich
    pkgs.python3Packages.scapy
    pkgs.python3Packages.urllib3
  ];

  env = {
    LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
      pkgs.stdenv.cc.cc
    ];

    POETRY_VIRTUALENVS_IN_PROJECT = "true";
    POETRY_VIRTUALENVS_PATH = "{project-dir}/.venv";

    POETRY_VIRTUALENVS_PREFER_ACTIVE_PYTHON = "true";
  };
}
  
  
  

  
  

