@echo off
call :GET_CURRENT_DIR
cd %THIS_DIR%
set /p AGAMA_DIR="Agama directory, followed by [ENTER]:"
echo "Removing old binaries"
rmdir /s %AGAMA_DIR%\resources\app\assets\bin\win64\verusd
MKDIR %AGAMA_DIR%\resources\app\assets\bin\win64\verusd
echo "Copying files"
xcopy /E %AGAMA_DIR%\resources\app\assets\bin\win64\verusd
ren %AGAMA_DIR%\resources\app\assets\bin\win64\verusd\komodod.exe %AGAMA_DIR%\resources\app\assets\bin\win64\verusd\verusd.exe
echo "Upgrade complete"

:GET_CURRENT_DIR
@pushd %~dp0
@set THIS_DIR=%CD%
@popd
@goto :EOF
