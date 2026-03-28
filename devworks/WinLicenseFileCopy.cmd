@echo off
title Copy Windows License Files
echo ========================================
echo Copying Windows License Files
echo ========================================
echo.

set "DEST_DIR=%USERPROFILE%\Desktop\License_Files"

if not exist "%DEST_DIR%" mkdir "%DEST_DIR%"

echo [1] Stopping Software Protection service...
net stop sppsvc /y >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Could not stop service, trying anyway...
)
echo.

:: File 1
set "SOURCE1=C:\Windows\System32\7B296FB0-376B-497e-B012-9C450E1B7327-5P-0.C7483456-A289-439d-8115-601632D005A0"
set "NAME1=7B296FB0-376B-497e-B012-9C450E1B7327-5P-0.C7483456-A289-439d-8115-601632D005A0"
set "DEST1=%DEST_DIR%\%NAME1%"

echo [2] Copying file 1: %NAME1%
if exist "%SOURCE1%" (
    robocopy "C:\Windows\System32" "%DEST_DIR%" "%NAME1%" /B >nul 2>&1
    if errorlevel 8 (
        echo [ERROR] Failed to copy file 1!
    ) else (
        attrib -s -h "%DEST1%" >nul 2>&1
        echo [OK] File 1 copied successfully!
        for %%A in ("%DEST1%") do echo     Size: %%~zA bytes
    )
) else (
    echo [SKIP] File 1 not found
)
echo.

:: File 2
set "SOURCE2=C:\Windows\System32\7B296FB0-376B-497e-B012-9C450E1B7327-5P-1.C7483456-A289-439d-8115-601632D005A0"
set "NAME2=7B296FB0-376B-497e-B012-9C450E1B7327-5P-1.C7483456-A289-439d-8115-601632D005A0"
set "DEST2=%DEST_DIR%\%NAME2%"

echo [3] Copying file 2: %NAME2%
if exist "%SOURCE2%" (
    robocopy "C:\Windows\System32" "%DEST_DIR%" "%NAME2%" /B >nul 2>&1
    if errorlevel 8 (
        echo [ERROR] Failed to copy file 2!
    ) else (
        attrib -s -h "%DEST2%" >nul 2>&1
        echo [OK] File 2 copied successfully!
        for %%A in ("%DEST2%") do echo     Size: %%~zA bytes
    )
) else (
    echo [SKIP] File 2 not found
)
echo.

echo [4] Restarting Software Protection service...
net start sppsvc >nul 2>&1

echo.
echo ========================================
echo Results saved to: %DEST_DIR%
echo ========================================
dir "%DEST_DIR%" /b
echo.
pause
