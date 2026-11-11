; Inno Setup script for UScan. Built by .github/workflows/release.yml:
;   ISCC.exe /DAppVersion=0.5.0 /DSourceDir=<publish dir> /DClamAVDir=<ClamAV files> installer\UScan.iss
; Installs UScan for all users and, with ClamAVDir, the official ClamAV build next to it: clamd runs
; as a Windows service (starts with Windows, restarts after a crash, signed-in users may start it),
; signatures are downloaded during setup and refreshed every 4 hours by a scheduled task.
; Command line: /SKIPSIGNATURES=1 skips the signature download (CI tests use their own test signature).
; Uninstall removes UScan, its ClamAV, the service, the task and the signatures; %LOCALAPPDATA%\UScan
; (reports, quarantine) is kept.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\publish\UScan"
#endif
#ifndef ClamAVDir
  #define ClamAVDir ""
#endif

[Setup]
AppId={{6F1C3E52-8B0A-4C55-9D7B-2E4A1F0B7C31}
AppName=UScan
AppVersion={#AppVersion}
AppPublisher=UScan
DefaultDirName={autopf}\UScan
DefaultGroupName=UScan
DisableProgramGroupPage=yes
UsePreviousAppDir=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19045
OutputBaseFilename=UScan-{#AppVersion}-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\UScan.exe
InfoAfterFile={#SourceDir}\LIESMICH.txt

[Languages]
Name: "de"; MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: "desktopicon"; Description: "Verknüpfung auf dem Desktop anlegen"; GroupDescription: "Zusätzliche Verknüpfungen:"

[Dirs]
Name: "{commonappdata}\UScan\ClamAV-Datenbank"; Permissions: users-modify

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs
#if ClamAVDir != ""
Source: "{#ClamAVDir}\*"; DestDir: "{app}\ClamAV"; Flags: ignoreversion recursesubdirs
#endif

[Icons]
Name: "{autoprograms}\UScan"; Filename: "{app}\UScan.exe"
Name: "{autodesktop}\UScan"; Filename: "{app}\UScan.exe"; Tasks: desktopicon

[UninstallDelete]
Type: filesandordirs; Name: "{app}\ClamAV"
Type: filesandordirs; Name: "{commonappdata}\UScan\ClamAV-Datenbank"
Type: dirifempty; Name: "{commonappdata}\UScan"

[Run]
Filename: "{app}\UScan.exe"; Description: "UScan jetzt starten"; Flags: nowait postinstall skipifsilent

[Code]
const
  ServiceKey = 'SYSTEM\CurrentControlSet\Services\clamd';
  OldPerUserKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{6F1C3E52-8B0A-4C55-9D7B-2E4A1F0B7C31}_is1';
  TaskName = 'UScan\ClamAV-Signaturen';
  { Default rights plus: signed-in users (AU) may query and start the service, so UScan can start it without admin rights. }
  ServiceSddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPLOCRRC;;;AU)';

var
  ManageClamAV: Boolean;

function ClamDir: String;
begin
  Result := ExpandConstant('{app}\ClamAV');
end;

function DbDir: String;
begin
  Result := ExpandConstant('{commonappdata}\UScan\ClamAV-Datenbank');
end;

function Sc(const Params: String): Integer;
var
  Code: Integer;
begin
  if not Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  Result := Code;
end;

function Schtasks(const Params: String): Integer;
var
  Code: Integer;
begin
  if not Exec(ExpandConstant('{sys}\schtasks.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  Result := Code;
end;

function ServiceImagePath(var Path: String): Boolean;
begin
  Result := RegQueryStringValue(HKLM, ServiceKey, 'ImagePath', Path);
end;

function IsOurService(const ImagePath: String): Boolean;
begin
  Result := Pos(Lowercase(ClamDir), Lowercase(ImagePath)) > 0;
end;

procedure StopService;
begin
  Sc('stop clamd');
  Sleep(4000);
end;

function PrepareToInstall(var NeedsRestartAfterInstall: Boolean): String;
var
  Uninstall, Image: String;
  Code: Integer;
begin
  Result := '';
  ManageClamAV := True;
#if ClamAVDir == ""
  ManageClamAV := False;
#endif

  { Versions before 0.6.0 were installed per user; remove that copy so only one UScan remains. Data is kept. }
  if RegQueryStringValue(HKCU, OldPerUserKey, 'UninstallString', Uninstall) then
    Exec(RemoveQuotes(Uninstall), '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '', SW_HIDE, ewWaitUntilTerminated, Code);

  if ManageClamAV and ServiceImagePath(Image) then
  begin
    if IsOurService(Image) then
      StopService { update: the running clamd.exe would block copying the new files }
    else if SuppressibleMsgBox('Auf diesem PC ist schon ein ClamAV-Dienst (clamd) eingerichtet:' + #13#10 + Image + #13#10#13#10 +
        'Soll UScan ihn durch das mitgelieferte ClamAV ersetzen? Dann richtet das Setup alles selbst ein (Dienst, Signaturen, automatische Updates). ' +
        'Der alte ClamAV-Ordner wird nicht gelöscht.' + #13#10#13#10 + 'Bei "Nein" bleibt dein vorhandener ClamAV-Dienst unverändert.',
        mbConfirmation, MB_YESNO, IDNO) = IDYES then
    begin
      StopService;
      Sc('delete clamd');
      Sleep(2000);
    end
    else
      ManageClamAV := False;
  end;
end;

procedure WriteConfigs;
var
  Db: String;
begin
  Db := DbDir;
  SaveStringToFile(ClamDir + '\clamd.conf',
    '# Vom UScan-Setup geschrieben. ClamAV ist nur von diesem PC aus erreichbar.' + #13#10 +
    'TCPSocket 3310' + #13#10 +
    'TCPAddr 127.0.0.1' + #13#10 +
    'DatabaseDirectory ' + Db + #13#10 +
    'LogFile ' + Db + '\clamd.log' + #13#10 +
    'LogFileMaxSize 5M' + #13#10 +
    'LogTime yes' + #13#10 +
    'SelfCheck 600' + #13#10 +
    'StreamMaxLength 100M' + #13#10 +
    'MaxFileSize 100M' + #13#10 +
    'MaxScanSize 400M' + #13#10 +
    'MaxFiles 10000' + #13#10 +
    'AlertExceedsMax yes' + #13#10 +
    'AlertEncrypted yes' + #13#10, False);
  SaveStringToFile(ClamDir + '\freshclam.conf',
    '# Vom UScan-Setup geschrieben.' + #13#10 +
    'DatabaseDirectory ' + Db + #13#10 +
    'UpdateLogFile ' + Db + '\freshclam.log' + #13#10 +
    'LogFileMaxSize 2M' + #13#10 +
    'LogTime yes' + #13#10 +
    'DatabaseMirror database.clamav.net' + #13#10, False);
  SaveStringToFile(ClamDir + '\uscan-managed.txt',
    'Dieser ClamAV wird vom UScan-Setup verwaltet (Dienst clamd, Aufgabe ' + TaskName + ').' + #13#10, False);
end;

procedure SetUpClamAV;
var
  Code: Integer;
  Image: String;
  SignaturesOk: Boolean;
begin
  WriteConfigs;

  SignaturesOk := True;
  if ExpandConstant('{param:SKIPSIGNATURES|0}') <> '1' then
  begin
    WizardForm.StatusLabel.Caption := 'Lade die Virensignaturen von ClamAV (über 200 MB, das kann einige Minuten dauern) ...';
    SignaturesOk := Exec(ClamDir + '\freshclam.exe', '--stdout --config-file="' + ClamDir + '\freshclam.conf"', ClamDir, SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
  end;

  WizardForm.StatusLabel.Caption := 'Richte den ClamAV-Dienst ein und starte ihn ...';
  if not ServiceImagePath(Image) then
    Exec(ClamDir + '\clamd.exe', '--install-service', ClamDir, SW_HIDE, ewWaitUntilTerminated, Code);
  Sc('config clamd start= auto');
  Sc('failure clamd reset= 86400 actions= restart/5000/restart/5000/restart/60000');
  Sc('sdset clamd ' + ServiceSddl);
  Sc('start clamd');

  Schtasks('/Create /F /TN "' + TaskName + '" /SC HOURLY /MO 4 /RU SYSTEM /RL HIGHEST /TR "\"' + ClamDir + '\freshclam.exe\" --quiet --config-file=\"' + ClamDir + '\freshclam.conf\""');

  if not SignaturesOk then
    SuppressibleMsgBox('Die Virensignaturen konnten gerade nicht geladen werden (keine Internetverbindung?).' + #13#10#13#10 +
      'Ohne Signaturen startet ClamAV nicht. UScan lädt sie automatisch alle 4 Stunden nach; du kannst auch in UScan auf der Übersicht ' +
      '"Signaturen aktualisieren" klicken. Danach startet UScan ClamAV selbst.', mbInformation, MB_OK, IDOK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and ManageClamAV then
    SetUpClamAV;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Image: String;
begin
  if (CurUninstallStep = usUninstall) and FileExists(ClamDir + '\uscan-managed.txt') then
  begin
    Schtasks('/Delete /F /TN "' + TaskName + '"');
    if ServiceImagePath(Image) and IsOurService(Image) then
    begin
      StopService;
      Sc('delete clamd');
    end;
  end;
end;
