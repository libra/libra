#!/bin/bash

# Copyright (c) The Diem Core Contributors
# SPDX-License-Identifier: Apache-2.0

# run this script from the project root using `./scripts/build_docs.sh`

function usage() {
  echo "Usage: $0 [-b] [-r] [-p]"
  echo ""
  echo "Build Diem documentation."
  echo ""
  echo "  -b   Build static version of documentation (otherwise start server)"
  echo ""
  echo "  -r   Build Diem Rust crate documentation"
  echo ""
  echo "  -p   Build Diem Python Client SDK documentation"
  echo ""
}

function install_rustup {
  echo "Installing Rust......"
  if rustup --version &>/dev/null; then
    echo "Rust is already installed"
  else
    curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable
    PATH="${HOME}/.cargo/bin:${PATH}"
  fi
}

function check_for_python {
  echo "Check for at least Python 3.7....."
  if python -c 'import sys; assert sys.version_info >= (3,7)' &>/dev/null; then
    echo "Python 3 is already installed with version: "
    python -c 'import sys; print(sys.version_info[:])'
  else
    echo "This requires at least Python 3.7. You have: "
    python -c 'import sys; print(sys.version_info[:])'
    echo "Install Python 3 from https://www.python.org/"
    exit 1
  fi
}

BUILD_STATIC=false
BUILD_RUSTDOCS=false
BUILD_PYTHON_SDK_DOCS=false

if [[ "$(basename $PWD)" != "developers.diem.com" ]]; then
  echo "Didn't pass directory check."
  echo ""
  echo "The script must be run from the developers.diem.com directory via ./scripts/build_docs.sh"
  echo ""
  echo "You are running it from: "
  echo $(echo $(basename $PWD))
  echo ""
  exit 1
fi

while getopts 'hbrp' flag; do
  case "${flag}" in
    h)
      usage;
      exit 0;
      ;;
    b)
      BUILD_STATIC=true
      ;;
    r)
      BUILD_RUSTDOCS=true
      ;;
    p)
      BUILD_PYTHON_SDK_DOCS=true
      ;;
    *)
      usage;
      exit 0;
      ;;
  esac
done

# Install Rust (Netlify will need this for website previews, for example)
install_rustup

if [[ $BUILD_RUSTDOCS == true ]]; then
  echo "-----------------------------------"
  echo "Generating API reference via Rustdoc"
  echo "-----------------------------------"

  # Back to the Diem repo root dir
  cd ..

  # Build the rust crate docs
  # Use `RUSTC_BOOTSTRAP` in order to use the `--enable-index-page` flag of rustdoc
  # This is needed in order to generate a landing page `index.html` for workspaces
  export PATH="$PATH:$HOME/.cargo/bin"
  RUSTC_BOOTSTRAP=1 RUSTDOCFLAGS="-Z unstable-options --enable-index-page" cargo doc --no-deps --workspace --lib || exit 1
  # Use the '.' to make sure we only copy the content from the doc dir, not the doc dir itself too.
  # Avoids having developers.diem.com/docs/rustdocs/doc. We want developers.diem.com/docs/rustdocs/
  RUSTDOC_DIR='../target/doc/.'
  DOCUSAURUS_RUSTDOC_DIR='static/docs/rustdocs/'
  cd developers.diem.com || exit

  mkdir -p $DOCUSAURUS_RUSTDOC_DIR
  cp -r $RUSTDOC_DIR $DOCUSAURUS_RUSTDOC_DIR
fi

if [[ $BUILD_PYTHON_SDK_DOCS == true ]]; then
  echo "-----------------------------------"
  echo "Generating Python Client SDK Docs"
  echo "-----------------------------------"

  echo "Checking for Python"
  check_for_python

  echo "Create directory for docs"
  rm -rf static/docs/python-client-sdk-docs/
  mkdir -p static/docs/python-client-sdk-docs/

  echo "Setting up Python virtual environment"
  python3 -m venv ./venv
  source ./venv/bin/activate

  echo "Installing pip, diem-client-sdk, pdoc3"
  ./venv/bin/pip install --upgrade pip
  ./venv/bin/pip install --pre diem-client-sdk
  ./venv/bin/pip install pdoc3

  echo "Generating doc from diem-client-sdk"
  ./venv/bin/pdoc3 diem --html -o static/docs/python-client-sdk-docs/

  echo "Shutdown virtual environment"
  deactivate
  rm -rf venv
fi

echo "-----------------------------------"
echo "Building Docusaurus 🦖"
echo "-----------------------------------"
yarn install

if [[ $BUILD_STATIC == true ]]; then
  echo "-----------------------------------"
  echo "Building static site"
  echo "-----------------------------------"
  yarn build
else
  echo "-----------------------------------"
  echo "Starting local server"
  echo "-----------------------------------"
  yarn start
fi
