#!/usr/bin/env fish

# Release script for swg
# Usage: ./scripts/release.fish [patch|minor|major]

set -l bump_type $argv[1]

if test -z "$bump_type"
    set bump_type "patch"
end

if not contains $bump_type patch minor major
    echo "Usage: release.fish [patch|minor|major]"
    echo "  patch - 0.0.X (default)"
    echo "  minor - 0.X.0"
    echo "  major - X.0.0"
    exit 1
end

# Ensure we're on master and up to date
set -l current_branch (git branch --show-current)
if test "$current_branch" != "master"
    echo "Error: Must be on master branch (currently on $current_branch)"
    exit 1
end

echo "Fetching latest tags..."
git fetch --tags

# Get latest tag, default to v0.0.0 if none exist
set -l latest_tag (git describe --tags --abbrev=0 2>/dev/null)
if test -z "$latest_tag"
    set latest_tag "v0.0.0"
end

echo "Latest tag: $latest_tag"

# Parse version components (strip 'v' prefix)
set -l version (string replace 'v' '' $latest_tag)
set -l parts (string split '.' $version)
set -l major $parts[1]
set -l minor $parts[2]
set -l patch $parts[3]

# Handle missing parts
if test -z "$major"; set major 0; end
if test -z "$minor"; set minor 0; end
if test -z "$patch"; set patch 0; end

# Bump version
switch $bump_type
    case patch
        set patch (math $patch + 1)
    case minor
        set minor (math $minor + 1)
        set patch 0
    case major
        set major (math $major + 1)
        set minor 0
        set patch 0
end

set -l new_tag "v$major.$minor.$patch"

echo ""
echo "Version bump: $latest_tag → $new_tag"
echo ""

# Confirm
read -l -P "Create and push tag $new_tag? [y/N] " confirm
if test "$confirm" != "y" -a "$confirm" != "Y"
    echo "Aborted."
    exit 0
end

# Ensure working directory is clean
if test -n "(git status --porcelain)"
    echo "Error: Working directory not clean. Commit or stash changes first."
    exit 1
end

# Create and push tag
echo "Creating tag $new_tag..."
git tag -a $new_tag -m "Release $new_tag"

echo "Pushing tag to origin..."
git push origin $new_tag

echo ""
echo "Done! Release $new_tag triggered."
echo "Watch progress at: https://github.com/acmacalister/swg/actions"
