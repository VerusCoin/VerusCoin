@ECHO OFF
TASKLIST /FI "IMAGENAME eq verusd.exe" 2>NUL | find /I /N "verusd.exe">NUL
if "%ERRORLEVEL%"=="0" EXIT 1
SET PROCESS_NAME=Verus Bootstrap
TASKLIST /V /NH /FI "imagename eq cmd.exe"| FIND /I /C "%PROCESS_NAME%" >NUL
IF %ERRORLEVEL%==0 EXIT 1
TITLE %PROCESS_NAME%

SETLOCAL EnableDelayedExpansion
SET BOOTSTRAP_URL=https://bootstrap.verus.io
SET TAR_FOUND=0
FOR %%x in (tar.exe) DO IF NOT [%%~$PATH:x]==[] SET TAR_FOUND=1
IF %TAR_FOUND% EQU 1 (
    SET BOOTSTRAP_PACKAGE=VRSC-bootstrap.tar.gz
) ELSE (
    SET BOOTSTRAP_PACKAGE=VRSC-bootstrap.zip
)
SET BOOTSTRAP_PACKAGE_SIG=!BOOTSTRAP_PACKAGE!.verusid
SET BLOCKCHAIN_DATA_FILES=fee_estimates.dat, komodostate, komodostate.ind, peers.dat, db.log, debug.log, signedmasks
SET BLOCKCHAIN_DATA_DIRS=blocks, chainstate, database

CALL :MAIN

:MAIN
    CD !Temp!
    SET "DOWNLOAD_CMD="
    FOR %%x IN (CURL.EXE BITSADMIN.EXE) DO IF NOT [%%~$PATH:x]==[] IF NOT DEFINED DOWNLOAD_CMD SET "DOWNLOAD_CMD=FETCH_%%x"
    CALL :SET_INSTALL_DIR
    SET "USE_BOOTSTRAP=1"
    DEL /Q/S "!Temp!\!BOOTSTRAP_PACKAGE_SIG!" >NUL
    IF NOT EXIST "!VRSC_DATA_DIR!" (
        ECHO No VRSC data directory found, creating directory.
        MD "!VRSC_DATA_DIR!"
    )
    CALL :CHECK_BLOCKCHAIN_DATA
    IF /I "!USE_BOOTSTRAP!" EQU "0" (
        CHOICE  /C:12 /N /M "Existing blockchain data found. Overwrite? ([1]Yes/[2]No)"%1
        IF !ERRORLEVEL! EQU 1 (
            CALL :CLEAN_BLOCKCHAIN_DATA
        ) ELSE (
            ECHO Bootstrap not installed
            EXIT 1
        )
     )
    CALL :FETCH_BOOTSTRAP
    EXIT 0
GOTO :EOF

:SET_INSTALL_DIR
    SET VRSC_DATA_DIR=""
    SET /P VRSC_DATA_DIR=Enter blockchain data directory or leave blank for default:
    IF !VRSC_DATA_DIR! == "" (
        SET "VRSC_DATA_DIR=%APPDATA%\Komodo\VRSC"
    )
    CHOICE  /C:12 /N /M "Install bootstrap in !VRSC_DATA_DIR!? ([1]Yes/[2]No)"%1
    IF !ERRORLEVEL! EQU 2 EXIT 1
GOTO :EOF

:FETCH_BITSADMIN.EXE
    SET "filename=%~1"
    SET "URL=%~2"
    CALL bitsadmin /transfer "Downloading %filename%" /priority FOREGROUND /download "%URL%/%filename%" "%Temp%\%filename%"
GOTO :EOF

:FETCH_CURL.EXE
    SET "filename=%~1"
    SET "URL=%~2"
    curl -# -L -C - "%URL%/%filename%" -o "%Temp%/%filename%"
GOTO :EOF

:CLEAN_UP_DOWNLOADS
    DEL /Q/S "!Temp!\!BOOTSTRAP_PACKAGE!" >NUL
    DEL /Q/S "!Temp!\!BOOTSTRAP_PACKAGE_SIG!" >NUL
GOTO :EOF

:CHECK_BLOCKCHAIN_DATA
    FOR %%F IN (!BLOCKCHAIN_DATA_FILES!) DO (
        IF  EXIST "!VRSC_DATA_DIR!\%%F" (
            ECHO Found "!VRSC_DATA_DIR!\%%F"
            SET USE_BOOTSTRAP=0
        )
    )
    FOR /D %%D IN (!BLOCKCHAIN_DATA_DIRS!) DO (
        IF EXIST "!VRSC_DATA_DIR!\%%D" (
            ECHO Found "!VRSC_DATA_DIR!\%%D"
            SET USE_BOOTSTRAP=0
        )
    )
GOTO :EOF

:CLEAN_BLOCKCHAIN_DATA
    FOR %%F IN (!BLOCKCHAIN_DATA_FILES!) DO (
        IF  EXIST "!VRSC_DATA_DIR!\%%F" (
            ECHO Removing "!VRSC_DATA_DIR!\%%F"
            DEL /Q/S "!VRSC_DATA_DIR!\%%F" >NUL
        )
    )
    FOR /D %%D IN (!BLOCKCHAIN_DATA_DIRS!) DO (
        IF EXIST "!VRSC_DATA_DIR!\%%D" (
            ECHO Removing "!VRSC_DATA_DIR!\%%D"
            DEL /Q/S  "!VRSC_DATA_DIR!\%%D" >NUL
        )
    )
GOTO :EOF

:FETCH_BOOTSTRAP
     ECHO Fetching VRSC bootstrap
        CALL :!DOWNLOAD_CMD! !BOOTSTRAP_PACKAGE!  !BOOTSTRAP_URL!
        CALL :!DOWNLOAD_CMD! !BOOTSTRAP_PACKAGE_SIG! !BOOTSTRAP_URL!
        ECHO Verifying download
        SET "filehash="
        CALL :GET_SHA256SUM "!Temp!\!BOOTSTRAP_PACKAGE!" filehash
        FINDSTR /m "!filehash!" "!Temp!\!BOOTSTRAP_PACKAGE_SIG!" >Nul
        IF !ERRORLEVEL! EQU 0 (
            ECHO Checksum verified!
            ECHO Extracting Verus blockchain bootstrap
            IF %TAR_FOUND% EQU 1  (
                tar -xf "!Temp!\!BOOTSTRAP_PACKAGE!" --directory "!VRSC_DATA_DIR!"
            ) ELSE (
                CALL :UNZIPFILE "!VRSC_DATA_DIR!" "!Temp!\!BOOTSTRAP_PACKAGE!"
            )
            ECHO Bootstrap successfully installed at "!VRSC_DATA_DIR!"
            CALL :CLEAN_UP_DOWNLOADS
        ) ELSE (
	        ECHO "!filehash!"
            ECHO Failed to verify bootstrap checksum
            CALL :CLEAN_UP_DOWNLOADS
            EXIT 1
        )
    )
GOTO :EOF

:GET_SHA256SUM
    SET "file=!%~1!"
    SET "sha256sum="
    FOR /f "skip=1 tokens=* delims=" %%# IN ('certutil -hashfile !file! SHA256') DO (
        IF NOT DEFINED sha256sum (
            FOR %%Z IN (%%#) DO SET "sha256sum=!sha256sum!%%Z"
        )
    )
    SET "%~2=!sha256sum!"
GOTO :EOF

:UNZIPFILE <ExtractTo> <ZipFile>
SET vbs="%temp%\_.vbs"
    IF EXIST %vbs% del /f /q %vbs%
    >%vbs%  echo Set fso = CreateObject("Scripting.FileSystemObject")
    >>%vbs% echo If NOT fso.FolderExists(%1) Then
    >>%vbs% echo fso.CreateFolder(%1)
    >>%vbs% echo End If
    >>%vbs% echo set objShell = CreateObject("Shell.Application")
    >>%vbs% echo set FilesInZip=objShell.NameSpace(%2).items
    >>%vbs% echo objShell.NameSpace(%1).CopyHere(FilesInZip)
    >>%vbs% echo Set fso = Nothing
    >>%vbs% echo Set objShell = Nothing
    cscript //nologo %vbs%
    IF EXIST %vbs% del /f /q %vbs%
GOTO :EOF
ENDLOCAL
