# RedForest Toolkit
<p align="center">
  <img src="https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExeG1uMjhlN2lpNnVmMm5wMTluZDJ6c3M2eXRnc3o0dmk0cXA2YnA2eiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MjZT6iMhEvobAY3PQG/giphy.gif" width="1000" />
</p>

> A curated toolkit of utilities, executables, PowerShell scripts, DLLs, and reference notes gathered to support Active Directory research, red teaming lab work, and defensive testing in isolated environments.

---

## Warning / Responsible Use
**This repository contains offensive security tools and potentially dangerous binaries.** Use **only** in environments you own or where you have explicit written authorization. Do **not** run these tools on production systems, customer networks, or any environment where you lack permission. Follow all applicable laws, organizational policies, and responsible disclosure practices.

Run everything in a safe, isolated lab (e.g., air-gapped VMs, snapshots you can revert) and verify file integrity (hashes, vendor/source) before execution.

---

## Repository contents (directory tree)
- **dlls/**
  - libeay32.dll
  - PowerShdll_x64.dll
  - PowerShdll_x86.dll
  - SeBackupPrivilegeCmdLets.dll
  - SeBackupPrivilegeUtils.dll
  - ssleay32.dll

- **EXE/**
  - BetterSafetyKatz.exe
  - bypass-clm.exe
  - DefenderSwitch.exe
  - Farmer.exe
  - Fertiliser.exe
  - GoldenGMSA.exe
  - HarvestCrop.exe
  - Hello_Bypass.exe
  - Hello.exe
  - hfs.exe
  - LaZagne.exe
  - Loader.exe
  - MDE_Enum.exe
  - mimidrv.sys
  - mimikatz.exe
  - mimilib.dll
  - MS-RPRN.exe
  - nc64.exe
  - NimExec.exe
  - Power_Bypass.exe
  - RawCopy64.exe
  - RawCopy.exe
  - SafetyKatz.exe
  - SandboxDefender.exe
  - sqlcmd.exe
  - SQLRecon.exe
  - Sysmon64.exe
  - Sysmon.exe
  - Transcription_Bypass.exe
  - Watson.exe

- **ps1/**
  - ADACLScan.ps1
  - adconnect.ps1
  - ASREPRoast.ps1
  - CIPolicyParser.ps1
  - defender.ps1
  - DomainPasswordSpray.ps1
  - EnableAllTokenPrivs.ps1
  - ExpandDefenderSig.ps1
  - Find-PSRemotingLocalAdminAccess.ps1
  - Find-WMILocalAdminAccess.ps1
  - Get-LAPSPermissions.ps1
  - Get-MSSQLLinkPasswords.psm1
  - Inveigh.ps1
  - Invoke-ADSDPropagation.ps1
  - Invoke-EDRChecker.ps1
  - Invoke-Encode.ps1
  - Invoke-GMSAPasswordReader.ps1
  - Invoke-HoneypotBuster.ps1
  - Invoke-Mimikatz_old.ps1
  - Invoke-Mimikatz.ps1
  - Invoke-Mimi.ps1
  - Invoke-noPac.ps1
  - Invoke-Phant0m.ps1
  - Invoke-PowerShellTcpEx.ps1
  - Invoke-PowerShellTcp_Old.ps1
  - Invoke-PowerShellTcpOneLine.ps1
  - Invoke-PowerShellTcp.ps1
  - Invoke-SDPropagator.ps1
  - Invoke-SDPropagator.ps1.1
  - Invoke-SessionHunter.ps1
  - Invoke-SharpDPAPI.ps1
  - Invoke-SqlServer-Persist-StartupSp.psm1
  - jaws-enum.ps1
  - Nikhil_rev.ps1
  - Old_PowerView.ps1
  - powercat.ps1
  - PowerGPOAbuse.ps1
  - Powermad.ps1
  - PowerUp_Old.ps1
  - PowerUpSQL.ps1
  - PowerView.ps1
  - Pre2kSpray.ps1
  - PrivescCheck.ps1
  - PSUpload.ps1
  - RACE.ps1
  - ServerUntrustAccount.ps1
  - SessionGopher.ps1
  - Set-DCShadowPermissions.ps1
  - Set-TokenPrivilege.ps1
  - SharpHound.ps1
  - winPEAS.ps1
  - Import-ActiveDirectory.ps1

- **txt/**
  - Amsi.txt
  - sbloggingbypass.txt

- **Python/**
  - fgpp.py

## What this toolkit is for
- **Research & learning:** quick access to binaries and scripts commonly referenced in AD research and red-team demos.  
- **Lab work:** reproduce scenarios in isolated test domains to learn detection and mitigation.  
- **Defensive development:** defenders can use these artifacts (in a safe lab) to validate detections, telemetry, and alerting logic.

## License & disclaimer
This repository is provided **AS IS** for research, education, and defensive testing only. The maintainers are not responsible for misuse. By using these materials you agree to comply with applicable laws and ethical guidelines. Consider adding a specific license file (e.g., MIT, or a responsible-use / prohibited-use clause) that matches your intent.

---
