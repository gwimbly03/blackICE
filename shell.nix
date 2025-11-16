{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = [
    pkgs.python3
    pkgs.poetry
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
  
  
  

  
  

