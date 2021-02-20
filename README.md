# UACHooker POC
Reflective DLL that hooks the AicLaunchAdminProcess function used in the explorer.exe for privilege escalation by hijacking the UAC prompt to trick the user. Copy your payload to "C:\Windows\Temp\test.exe" (currently hardcoded). 

`inject.exe (ps -name explorer).id UACHookerDll.dll`

Whenever the user tries to open powershell or cmd as admin, it will append to the arguments to execute the payload instead. The user can still see the suspicious arguments if "Show more details" is clicked, but who does that?
![pwsh demo](https://github.com/TheKevinWang/UACHooker/blob/main/pwsh.PNG)
Whenever the user tries to open any other program as admin, it will instead rename the payload to the same name as the original, set the arguments to the same as the original,
and execute the payload instead. The "Program location" field displayed when the user clicks "Show more details" shows the arguments
to the program, with the assumption that the first argument is the path, but of course this can be spoofed. 
For an unsigned .exe, the malicious UAC prompt will be indistinguishable from the real one! For whatever reason, there is no way to view the real path to the exe in the UAC prompt.
I have informed Microsoft, but they do not consider this a vulnerability.
![unsigned exe demo](https://github.com/TheKevinWang/UACHooker/blob/main/unsigned.PNG)

*It's actually C:\Windows\Temp\test.exe not C:\Users\Test\Downloads\unetbootin.exe!*
# Future
Currently, only Detours can be used for the hooking. However, Polyhook2 will be supported as well in the future. 
Currently a POC, but a full fledged version is in the works. 
Also, investigate targets beyond explorer.exe. 
