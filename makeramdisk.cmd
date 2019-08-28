@echo off
IF NOT "%AENV%"=="1" (
    echo "Environment missing, please rerun makeramdisk command"
    setenv.cmd
)

python root\scripts\makeramdisk.py %*