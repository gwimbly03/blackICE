{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = [
    pkgs.python314
    pkgs.poetry
    pkgs.python314Packages.cffi
    pkgs.python314Packages.charset-normalizer
    pkgs.python314Packages.cryptography
    pkgs.python314Packages.dnspython
    pkgs.python314Packages.idna
    pkgs.python314Packages.markdown-it-py
    pkgs.python314Packages.mdurl
    pkgs.python314Packages.orjson
    pkgs.python314Packages.psutil
    pkgs.python314Packages.pycparser
    pkgs.python314Packages.pygments
    pkgs.python314Packages.pyopenssl
    pkgs.python314Packages.pyyaml
    pkgs.python314Packages.readchar
    pkgs.python314Packages.requests
    pkgs.python314Packages.rich
    pkgs.python314Packages.scapy
    pkgs.python314Packages.urllib3
    pkgs.python314Packages.fastapi
    pkgs.python314Packages.uvicorn
    pkgs.nodejs_25

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
  
  
  

  
  

