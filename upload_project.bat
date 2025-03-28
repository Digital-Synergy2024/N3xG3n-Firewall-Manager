@echo off
REM Batch script to upload the entire project to GitHub

REM Set variables
SET REPO_URL=https://github.com/Digital-Synergy2024/NexG3n-Firewall-Manager.git
SET BRANCH_NAME=main
SET COMMIT_MESSAGE="Upload entire project"

REM Navigate to the project directory
cd /d "c:\Users\Dizzy\Desktop\NexG3n FireWall Manager"

REM Initialize Git repository (if not already initialized)
git init

REM Add the remote repository (if not already added)
git remote add origin %REPO_URL% 2>nul

REM Pull changes from the remote repository to avoid conflicts
git pull origin %BRANCH_NAME% --rebase

REM Add all files to the staging area
git add .

REM Commit the changes
git commit -m %COMMIT_MESSAGE%

REM Set the branch name to main (if not already set)
git branch -M %BRANCH_NAME%

REM Push the changes to the remote repository
git push -u origin %BRANCH_NAME%

REM Done
echo Project uploaded successfully to GitHub!
pause