@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
set > "%~dp0msvc_env.txt"
cd /d "%~dp0"
cargo build --verbose > "%~dp0build_verbose.log" 2>&1
echo %ERRORLEVEL% > "%~dp0build_exitcode.txt"
