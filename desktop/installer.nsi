; Event Solutions for Windows: installer (EventSolutions-Setup.exe)
; Installs for the current user only (no administrator rights needed) into
; %LOCALAPPDATA%\Programs\Event Solutions, adds Start menu and desktop shortcuts,
; starts the app. Running it again updates the app (closes the running one first).
; Build: ./build.sh (packs dist/win-unpacked with electron-builder, then makensis)

Unicode true
!ifndef SRC
  !define SRC "dist\win-unpacked"
!endif
!ifndef OUT
  !define OUT "dist\EventSolutions-Setup.exe"
!endif
!ifndef VERSION
  !define VERSION "1.0.0"
!endif
!define NAME "Event Solutions"
!define EXE "EventSolutions.exe"
!define AUMID "lt.eventsolutions.app"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${AUMID}"
!ifdef PLUGINS
  !addplugindir /x86-unicode "${PLUGINS}"
!endif

Name "${NAME}"
OutFile "${OUT}"
Icon "res\icon.ico"
UninstallIcon "res\icon.ico"
InstallDir "$LOCALAPPDATA\Programs\${NAME}"
RequestExecutionLevel user
SetCompressor /SOLID lzma
SetCompressorDictSize 64
ShowInstDetails nevershow
ShowUninstDetails nevershow
AutoCloseWindow true
BrandingText "${NAME} ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${NAME}"
VIAddVersionKey "FileDescription" "${NAME} diegimas"
VIAddVersionKey "CompanyName" "${NAME}"
VIAddVersionKey "LegalCopyright" "${NAME}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"

Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Function CloseApp
  nsExec::Exec 'taskkill /IM "${EXE}" /F'
  Pop $0
  Sleep 800
FunctionEnd
Function un.CloseApp
  nsExec::Exec 'taskkill /IM "${EXE}" /F'
  Pop $0
  Sleep 800
FunctionEnd

Section "Install"
  Call CloseApp
  SetOutPath "$INSTDIR"
  ; an older version's files (e.g. removed languages) must not stay behind
  RMDir /r "$INSTDIR\resources"
  RMDir /r "$INSTDIR\locales"
  File /r "${SRC}\*.*"
  WriteUninstaller "$INSTDIR\Uninstall ${NAME}.exe"

  ; shortcuts carry the app id, or Windows does not show its notifications
  CreateShortCut "$SMPROGRAMS\${NAME}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\${EXE}" 0
  WinShell::SetLnkAUMI "$SMPROGRAMS\${NAME}.lnk" "${AUMID}"
  CreateShortCut "$DESKTOP\${NAME}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\${EXE}" 0
  WinShell::SetLnkAUMI "$DESKTOP\${NAME}.lnk" "${AUMID}"

  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "${NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${EXE},0"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall ${NAME}.exe"'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1

  Exec '"$INSTDIR\${EXE}"'
SectionEnd

Section "Uninstall"
  Call un.CloseApp
  Delete "$SMPROGRAMS\${NAME}.lnk"
  Delete "$DESKTOP\${NAME}.lnk"
  ; "start together with Windows" (app.setLoginItemSettings)
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${AUMID}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "${AUMID}"
  DeleteRegKey HKCU "${UNINST_KEY}"
  RMDir /r "$INSTDIR"
SectionEnd
