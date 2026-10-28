; Inno Setup script for UScan. Built by .github/workflows/release.yml:
;   ISCC.exe /DAppVersion=0.5.0 /DSourceDir=<publish dir> installer\UScan.iss
; Installs per user (no admin rights). Uninstall leaves %LOCALAPPDATA%\UScan (reports, quarantine) untouched.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\publish\UScan"
#endif

[Setup]
AppId={{6F1C3E52-8B0A-4C55-9D7B-2E4A1F0B7C31}
AppName=UScan
AppVersion={#AppVersion}
AppPublisher=UScan
DefaultDirName={autopf}\UScan
DefaultGroupName=UScan
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19045
OutputBaseFilename=UScan-{#AppVersion}-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\UScan.exe
InfoAfterFile={#SourceDir}\LIESMICH.txt

[Languages]
Name: "de"; MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: "desktopicon"; Description: "Verknüpfung auf dem Desktop anlegen"; GroupDescription: "Zusätzliche Verknüpfungen:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{autoprograms}\UScan"; Filename: "{app}\UScan.exe"
Name: "{autodesktop}\UScan"; Filename: "{app}\UScan.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\UScan.exe"; Description: "UScan jetzt starten"; Flags: nowait postinstall skipifsilent
