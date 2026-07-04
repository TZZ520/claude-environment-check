Unicode true
RequestExecutionLevel user
Name "Claude Environment Check (Unofficial)"
OutFile "..\..\build\bin\ClaudeEnvironmentCheck-Setup-unsigned.exe"
InstallDir "$LOCALAPPDATA\Programs\ClaudeEnvironmentCheck"
SetCompressor /SOLID lzma

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Install"
  SetOutPath "$INSTDIR"
  File "..\..\build\bin\ClaudeEnvironmentCheck.exe"
  File "..\..\build\bin\claude-env-check.exe"
  File "..\..\README.md"
  File "..\..\LICENSE"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\Claude Environment Check"
  CreateShortcut "$SMPROGRAMS\Claude Environment Check\Claude Environment Check.lnk" "$INSTDIR\ClaudeEnvironmentCheck.exe"
  CreateShortcut "$SMPROGRAMS\Claude Environment Check\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\ClaudeEnvironmentCheck.exe"
  Delete "$INSTDIR\claude-env-check.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir /r "$SMPROGRAMS\Claude Environment Check"
  RMDir "$INSTDIR"
SectionEnd

