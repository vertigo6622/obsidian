@echo off
echo Make sure all the relevant build files are in this current folder, or the bat will fail.
echo Standby...
timeout 5 > nul
echo Building stub...
.\gcc.exe stub.c -o stub.o -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector
if %errorlevel% neq 0 (
    echo Failed to compile stub.c
)

timeout 2 > nul

echo Linking stub...
.\ld.exe stub.o -o stub.exe -nostdlib --build-id=none --entry=_start -s
if %errorlevel% neq 0 (
    echo Failed to link stub.exe
)

timeout 2 > nul

echo Converting to binary...
.\objcopy.exe -O binary stub.exe stub.bin
if %errorlevel% neq 0 (
    echo Failed to convert to binary
)

timeout 2 > nul

echo Truncating stub.bin...
python clean.py stub.bin
if %errorlevel% neq 0 (
    echo Failed to truncate stub
)

timeout 2 > nul

echo Building resource file...
.\windres.exe resource.rc -o resource.o
if %errorlevel% neq 0 (
    echo Failed to compile resource.c
)

timeout 2 > nul

echo Building crypter...
.\gcc.exe obsidian.c resource.o -o obsidian.exe -lbcrypt -I.
if %errorlevel% neq 0 (
    echo Failed to compile adv-crypter.c
)

echo Build completed successfully!
timeout 3 > nul
