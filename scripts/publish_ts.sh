#!/bin/bash

# fail if any command in script fails
set -e 

# This script handling the publishing of the current 
# commits typescript based library as an unstable package

# Example if the current package.json version reads 0.1.0 
# then the release will be tagged with 0.1.0

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# remove the generated binary as this will be fetch by node-gyp on package install
rm native/index.node

# Add in the install script to package.json
node scripts/add_stable_install_script.cjs

# Fetch the current version from the package.json
new_version=$(node -pe "require('./package.json').version")

# Version to this new unstable version
yarn publish --no-git-tag-version --new-version $new_version

# Reset changes to the package.json
git checkout -- package.json
      