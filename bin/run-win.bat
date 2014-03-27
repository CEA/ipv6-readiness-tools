@echo off

:: Determine host arch
Set RegQry=HKLM\Hardware\Description\System\CentralProcessor\0
REG.exe Query %RegQry% > CheckOS.txt
Find /i "x86" < CheckOS.txt > StringCheck.txt

:: Configure library path
If %ERRORLEVEL% == 0 (
    Set Lib=lib-native\jnetpcap\win32
) ELSE (
    Set Lib=lib-native\jnetpcap\win64
)

:: Cleanup
del CheckOS.txt
del StringCheck.txt

:: launch
java -Djava.library.path=%Lib% -jar v6App.jar