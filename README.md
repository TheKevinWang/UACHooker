# UACHooker
Reflective DLL that hooks the AicLaunchAdminProcess function used in the explorer.exe for privilege escalation.
Whenever the user tries to open powershell or cmd as admin, it will append to the arguments to execute the payload instead. The user can still see the suspicious arguments if "Show more details" is clicked, but who does that?
![pwsh demo](https://github.com/TheKevinWang/UACHooker/blob/main/pwsh.PNG)
Whenever the user tries to open any other program as admin, it will instead rename the payload to have the same name as the target, set the arguments to be the same as the original,
and execute the payload instead. The "Program location" field displayed when the user clicks "Show more details" shows the arguments
to the program, with the assumption that the first argument is the path, but of course this can be spoofed. 
For an unsigned .exe, the malicious UAC prompt will be indistinguishable from the real one! For whatever reason, there is no way to view the real path to the exe in the UAC prompt.
I have informed Microsoft, but they do not consider this a vulnerability.
![unsigned exe demo](https://github.com/TheKevinWang/UACHooker/blob/main/unsigned.PNG)
*Hooked prompt looks the exact same as the unhooked.*
# Future
Currently, only Detours can be used for the hooking. However, Polyhook2 will be supported as well in the future. 
Currently a POC. A more full fledged version is in the works. 
