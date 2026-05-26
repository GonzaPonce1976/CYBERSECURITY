@echo off
set INCLUDE=C:\PROGRA~1\MICROS~4\18\Community\SDK\ScopeCppSDK\vc15\VC\include;C:\PROGRA~2\WI3CF2~1\10\Include\10.0.26100.0\ucrt;C:\PROGRA~2\WI3CF2~1\10\Include\10.0.26100.0\um;C:\PROGRA~2\WI3CF2~1\10\Include\10.0.26100.0\shared
set LIB=C:\PROGRA~1\MICROS~4\18\Community\SDK\ScopeCppSDK\vc15\VC\lib;C:\PROGRA~1\MICROS~4\18\Community\SDK\ScopeCppSDK\vc15\SDK\lib;C:\PROGRA~2\WI3CF2~1\10\Lib\10.0.26100.0\um\x64;C:\PROGRA~2\WI3CF2~1\10\Lib\10.0.26100.0\ucrt\x64
cargo build --release
