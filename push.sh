#!/usr/bin/env bash
set -e

echo "Initializing Git repository..."
git init
git branch -M main
git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/SC136/TeamName_college_round.git

echo "Adding files..."
git add .

echo "Committing changes..."
git commit -m "feat: complete Incognito zero-knowledge privacy reporting system with Material 3 Expressive UI" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"

echo "Pushing to GitHub..."
git push -u origin main --force
echo "Done!"
