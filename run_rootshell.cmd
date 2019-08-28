@echo off
set PATH=%CD%\Tools;%CD%\Tools\python37;%CD%\Tools\python37\Scripts;%PATH%
adb forward tcp:1231 tcp:1231
echo Enter your commands below (root):
nc localhost 1231


