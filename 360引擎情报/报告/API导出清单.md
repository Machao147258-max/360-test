# 360 载荷 · 导出 API 清单

> 带导出的模块 **266** 个（x86 238 / x64 28），导出合计 **3202** 条。
> 只列导出（可被外部调用的 API），不含内部函数。机器可读版见 `api_exports.tsv`。

## IPC 服务(ipc/)  （16 模块 / 218 导出）
### `ipc/360Box.dll` (x86, 65 导出)
- `AddClientRule`, `AddClientRuleEx`, `AddExceptionObjectRuleBox`, `AddExceptionRule`, `AddMessageRuleToBox`, `AddMessageRuleToBox_3`, `AddMessageRuleToBox_4`, `AddMessageRuleToBox_BypassProcess`, `AddProtectedFile`, `AddProtectedFileEx`, `AddRule`, `AddSbrRetainRule`, `CleanSbrRetainRules`, `CleanupAllClientRules`, `CleanupAllRules`, `ClearTargetSandBox`, `CloseClientHandle`, `CloseClientSession`, `CreateClientHandle`, `CreateClientSession`, `DeleteAllFilesInSandBox`, `DeleteCustomSandBox`, `DeleteFileByPath`, `GetClientSessionHandle`, `GetDriverState`, `GetDriverStateEx`, `GetProcessFlags`, `GetSandboxSize`, `GetSandboxSizeEx`, `Install`, `InstallBySC`, `IsClientConnected`, `NotifyDriverClientResult`, `NotifyDriverResult`, `QueryDriverVersion`, `QueryIfFirstTryGoToSandbox`, `QueryNtNameByDriverLetter`, `QueryProtectedInformation`, `QuerySandBoxProcessInformation`, `QuerySandBoxProcessInformationEx`, `RemoveAllMessageRulesFromBox`, `RemoveAllObjectRuleBox`, `RemoveAllProtectedFile`, `RemoveAllProtectedFileEx`, `RemoveMessageRuleFromBox`, `RemoveMessageRuleFromBox_3`, `RemoveMessageRuleFromBox_4`, `RemoveMessageRuleFromBox_BypassProcess`, `RemoveObjectRuleBox`, `RemoveProtectedFile`, `RemoveProtectedFileEx`, `ReplyClientResult`, `SetHostEnable`, `SetProcessFlags`, `SetProcessFlagsEx`, `SetRestrictPermissionsBox`, `SetShutdownClearBox`, `SetSpecialPermissionsBox`, `SetupInstall`, `StartHook` …

### `ipc/sbmon.dll` (x86, 63 导出)
- `AddSbRule`, `CheckComponentVersionForR3Clean`, `CheckSandboxSupportOSVersion`, `CheckSandboxSupportSafevideo64`, `CleanFilesInSandbox`, `CleanupCustomSandBox`, `CleanupSandBox`, `ClearMapEx`, `CountSandboxSize`, `CountSandboxSizeEx`, `CountSandboxSizeWarningFreeSpace`, `EnumSbRuleItem`, `Execute360ProcessInSb`, `ExecuteNonPeBy360BoxLdInSb`, `ExecuteProcessInSb`, `ExecuteProcessInSbEx`, `ExecuteProcessInSbWithCmd`, `ExecuteProcessToSb5`, `GetSandBoxInformation`, `GetSandBoxQrosCfgValue`, `GetSandBoxRestrictStatus`, `GetSandBoxSupportValue`, `GetSandboxConnectionState`, `GetStrongEnvironment`, `GetStrongEnvironmentEx`, `GetStrongInfo`, `GetStrongInfoEx`, `IfProcessInXBS`, `IfProcessInXBS2`, `InstallEx`, `InstallEx32`, `InstallEx64`, `InstallSandBox`, `IsSandBoxRunning`, `LoadExceptionConfig`, `OnStartSandboxEx`, `OnStopSandboxEx`, `QueryInternalVersion`, `ReGetStrongInfoEx`, `ReadRuleFromFileEx`, `RegisterToSandbox`, `ReleaseSbRuleItem`, `RemoveSbRule`, `SandBoxSwitch`, `SbCheckProcess`, `SbGetInfo`, `SbGetInfoEx`, `SbxGetCleanOptionByIndex`, `SbxGetDescriptionByIndex`, `SbxGetNumberOfSetting`, `SbxSetCleanOptionByIndex`, `SetHostCallback`, `SetSandBoxInformation`, `SetSandboxBlockNet`, `SetSandboxProcessToND`, `SetSandboxWarningSizePercent`, `SetShutdownClear`, `TerminateProcessBySbRule`, `UnRegisterFromSandbox`, `UninstallEx` …

### `ipc/DrvUtility.dll` (x86, 17 导出)
- `CheckDrivers`, `CheckSupportOs`, `InstallDriverFor360SafeSetup`, `InstallDriverOnPackageCallEx`, `InstallDrivers`, `InstallHVM`, `InstallHookPortWin10x86`, `IsCameraExist`, `IsSupportOutwardAtkDefend`, `IsSupportVulnDefend`, `RepaireDrivers`, `SetDriverStart`, `StartDrivers`, `UnInstallDriverFor360SafeSetup`, `UnInstallDriverOnPackageCallEx`, `UnInstallDrivers`, `UpdateDriver`

### `ipc/qutmipc.dll` (x86, 14 导出)
- `AddExceptionRule`, `AddRawbRule`, `ClearMonpoint`, `Init`, `Install`, `ReadVirtualMemory`, `ReplyMonpoint`, `SetMonpoint`, `SetMonpoint2`, `SetupInstall`, `StartMon`, `StopMon`, `Uninit`, `Uninstall`

### `ipc/X64For32Lib.dll` (x86, 11 导出)
- `EnumProcessModules64`, `GetCommandLine64`, `GetCurrentDirectory64`, `GetModuleBaseNameW64`, `GetModuleFileNameExW64`, `GetModuleInformation64`, `IsProcessWow64Process`, `NtQueryInformationProcess64`, `NtQueryInformationThread64`, `NtQueryVirtualMemory64`, `ReadProcessMemory64`

### `ipc/appd.dll` (x86, 7 导出)
- `ADEnumProcessInfoFromSnapShot`, `ADForceStop`, `ADFreeSnapShot`, `ADGetActiveProcessSnapShot`, `CreateTrayClient`, `GetBrowserInPrivateState`, `GetExtInfo`

### `ipc/ipcService.dll` (x86, 7 导出)
- `CreateTrayClient`, `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `RegisterExtCallback`, `UnregisterExtCallback`

### `ipc/qutmvd.dll` (x86, 7 导出)
- `Init`, `Install`, `QueryInfo`, `StartMon`, `StopMon`, `Uninit`, `Uninstall`

### `ipc/360hvm.dll` (x86, 6 导出)
- `DoesBiosFeatureTouched`, `GetCpuInformation`, `GetDriverState`, `GetDriverVersion`, `GetStopReason`, `SlowFeatureControl`

### `ipc/NetDefender.dll` (x86, 6 导出)
- `CreateTrayClient`, `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `SetProcessContext`

### `ipc/appdext.dll` (x86, 5 导出)
- `appdext_001`, `appdext_002`, `appdext_003`, `appdext_004`, `appdext_005`

### `ipc/ChkDrvErr.dll` (x86, 3 导出)
- `CheckoutBrokeHips`, `CheckoutBrokeHipsEx`, `CheckoutBrokeHips_UserAction`

### `ipc/FileDef.dll` (x86, 3 导出)
- `NotifyFileDef`, `NotifyFileDef2`, `filedef_0001`

### `ipc/hipslog.dll` (x86, 2 导出)
- `CreateHipsLogReader`, `CreateHipsLogReaderEx`

### `ipc/FileMgr.dll` (x86, 1 导出)
- `CreateTrayClient`

### `ipc/yhregd.dll` (x86, 1 导出)
- `CreateTrayClient`

## 企业管控(EntAdmin/)  （1 模块 / 1 导出）
### `EntAdmin/360EntCloudData.dll` (x86, 1 导出)
- `CreateEntCloudDataMgr`

## 其它(360zip)  （1 模块 / 4 导出）
### `360zip/360zipw.dll` (x86, 4 导出)
- `CreateExtractObject`, `CreateNZPObject`, `DeleteExtractObject`, `DeleteNZPObject`

## 其它(Config)  （1 模块 / 1 导出）
### `Config/uninst/UninstDisplay.dll` (x86, 1 导出)
- `IsDisplayType`

## 其它(modules)  （1 模块 / 1 导出）
### `modules/AVCheck.dll` (x86, 1 导出)
- `InitAntiVirusScanEng`

## 实时防护/托盘(safemon/)  （88 模块 / 826 导出）
### `safemon/SomProxy.dll` (x86, 102 导出)
- `AddSearch`, `CheckSupportOs`, `ClearWDHistory`, `ClearWDHistoryDownloadItem`, `CreateKeepAlivePLugin`, `DeleteSearch`, `EnableUrlCloudSafe`, `FreeWDHistory`, `GetAthpState`, `GetBrowseList`, `GetDGWndNoPEState`, `GetDGWndSafeState`, `GetDmgrTipSwitch`, `GetEMailWndSafeState`, `GetEncZipState`, `GetIMDlLnkState`, `GetIMEncZipState`, `GetIMIDSafeStatus`, `GetIMWndNoPEState`, `GetIMWndSafeState`, `GetKanpianStatus`, `GetPayInsureState`, `GetSDOfficeWndSafeState`, `GetSearchBarV2Status`, `GetSearchProtect`, `GetSiteCardStatus`, `GetSuggestApkStatus`, `GetUserFileSafeInfo`, `GetWDDlLnkState`, `GetWDDownloadFileNum`, `GetWDGuardState`, `GetWDHistoryDownloadList`, `GetWDScanFileNum`, `HandlerChromePlug`, `Init360ualive`, `Install`, `IsDefaultSoSearch`, `IsLockSearch`, `IsLockSoSearch`, `IsNeedRepairChromePlugin`, `IsNeedRepairFireFoxPlugin`, `IsNeedRepairMsEdge`, `IsNeedRepairOperaPlugin`, `IsNeedRepairYandexPlugin`, `IsRepairLockDefaultSearch`, `IsSetHomePage`, `IsSetHomePageEx`, `IsSupportLockSearch`, `IsSupportPayInsure`, `IsSupportSuperBlank`, `IsUrlCloudSafeEnabled`, `IsWDSandBoxEnable`, `OnSetSafePages`, `OpenPayInsure`, `PayGuardDisable`, `PayGuardEnable`, `PayGuardGetPNum`, `PayGuardIsEnable`, `PayGuardIsSupport`, `PayGuardView` …

### `safemon/360RDPNLAProtect64.dll` (x64, 79 导出)
- `DoWork`, `cJSON_AddArrayToObject`, `cJSON_AddBoolToObject`, `cJSON_AddFalseToObject`, `cJSON_AddItemReferenceToArray`, `cJSON_AddItemReferenceToObject`, `cJSON_AddItemToArray`, `cJSON_AddItemToObject`, `cJSON_AddItemToObjectCS`, `cJSON_AddNullToObject`, `cJSON_AddNumberToObject`, `cJSON_AddObjectToObject`, `cJSON_AddRawToObject`, `cJSON_AddStringToObject`, `cJSON_AddTrueToObject`, `cJSON_Compare`, `cJSON_CreateArray`, `cJSON_CreateArrayReference`, `cJSON_CreateBool`, `cJSON_CreateDoubleArray`, `cJSON_CreateFalse`, `cJSON_CreateFloatArray`, `cJSON_CreateIntArray`, `cJSON_CreateNull`, `cJSON_CreateNumber`, `cJSON_CreateObject`, `cJSON_CreateObjectReference`, `cJSON_CreateRaw`, `cJSON_CreateString`, `cJSON_CreateStringArray`, `cJSON_CreateStringReference`, `cJSON_CreateTrue`, `cJSON_Delete`, `cJSON_DeleteItemFromArray`, `cJSON_DeleteItemFromObject`, `cJSON_DeleteItemFromObjectCaseSensitive`, `cJSON_DetachItemFromArray`, `cJSON_DetachItemFromObject`, `cJSON_DetachItemFromObjectCaseSensitive`, `cJSON_DetachItemViaPointer`, `cJSON_Duplicate`, `cJSON_GetArrayItem`, `cJSON_GetArraySize`, `cJSON_GetErrorPtr`, `cJSON_GetNumberValue`, `cJSON_GetObjectItem`, `cJSON_GetObjectItemCaseSensitive`, `cJSON_GetStringValue`, `cJSON_HasObjectItem`, `cJSON_InitHooks`, `cJSON_InsertItemInArray`, `cJSON_IsArray`, `cJSON_IsBool`, `cJSON_IsFalse`, `cJSON_IsInvalid`, `cJSON_IsNull`, `cJSON_IsNumber`, `cJSON_IsObject`, `cJSON_IsRaw`, `cJSON_IsString` …

### `safemon/SettingCenterCfg.dll` (x86, 61 导出)
- `Client_AsyncRemoveAmppl`, `GetBrowserLockState`, `GetBrowserState`, `GetDeskTopIconState`, `GetDesktopSideBarState`, `GetDevMode`, `GetDeviceProState`, `GetFixTrojanRelateFileState`, `GetHuaCiState`, `GetIMEBundleState`, `GetIMEProState`, `GetIMUrlProc`, `GetMagicCameraState`, `GetMobileMon`, `GetNetSafeProtectState`, `GetProtectSelfState`, `GetSbxProtectState`, `GetSbxUnknowFileProtectState`, `GetServiceState`, `GetSoftPrivMgrState`, `GetTrustDir`, `GetUDiskSideBarState`, `GetUdisk_Desk_Band`, `GetUdisk_Float_Wnd`, `GetUdisk_Link`, `GetUrlQueryState`, `GetWindowsDefenderState`, `IsIdUCenterLoad`, `IsShowMobileMon`, `IsShowWindowsDefenderSettingItem`, `NotifyWndSettingCmdInfo`, `ResetDrvState`, `SetBrowserLockState`, `SetBrowserState`, `SetDeskTopIconState`, `SetDesktopSideBarState`, `SetDevMode`, `SetDeviceProState`, `SetFixTrojanRelateFileState`, `SetHuaCiState`, `SetIMEBundleState`, `SetIMEProState`, `SetIMUrlProc`, `SetMagicCameraState`, `SetMobileMon`, `SetMsgBoxFlag`, `SetNetSafeProtectState`, `SetProtectSelfState`, `SetSbxProtectState`, `SetSbxUnknowFileProtectState`, `SetServiceState`, `SetServiceStateEx`, `SetSoftPrivMgrState`, `SetTrustDir`, `SetTrustDirNoCheck`, `SetUDiskSideBarState`, `SetUdisk_Desk_Band`, `SetUdisk_Float_Wnd`, `SetUdisk_Link`, `SetUrlQueryState` …

### `safemon/safemon.dll` (x86, 49 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `GetSafeVedioVersion`, `GetUrlSiteType`, `Initialize`, `IsInExplorer`, `IsTraystupidRealRunning`, `LogIEProtectInfo`, `SendCollectConfigInfo`, `SetMailGuardCallback`, `SetNetpayGuardState`, `SetSafeVedioVersion`, `SetWDPayProPopWndState`, `Start`, `StartF`, `Stop`, `Update`, `pcre_callout`, `pcre_compile`, `pcre_compile2`, `pcre_exec`, `pcre_free`, `pcre_malloc`, `pcre_stack_free`, `pcre_stack_malloc`, `safemon_100`, `safemon_101`, `safemon_102`, `safemon_103`, `safemon_104`, `safemon_105`, `safemon_106`, `safemon_107`, `safemon_108`, `safemon_109`, `safemon_110`, `safemon_111`, `safemon_112`, `safemon_113`, `safemon_114`, `safemon_115`, `safemon_116`, `safemon_117`, `safemon_118`, `safemon_119`, `safemoninit`, `updatesva`

### `safemon/ieplus.dll` (x86, 32 导出)
- `CreateBHO`, `GetAdFilterAdvState_old`, `GetAdblockEnable`, `GetAdblockLevel1`, `GetAdblockLevel2`, `GetAdblockLevel3`, `GetAdblockTipbar`, `GetFilterDeceiveInfo_old`, `GetPopTipForFilterAdv_BB_old`, `GetPopTipForFilterAdv_old`, `GetShowIEPlusIcon`, `GetState`, `GetTipForFilterDeceive_old`, `Init`, `IsOldAdfilterSupport`, `IsShowAdFilter`, `IsSupport`, `OnTrayMsg`, `SetAdFilterAdvState_old`, `SetAdblockEnable`, `SetAdblockLevel1`, `SetAdblockLevel2`, `SetAdblockLevel3`, `SetAdblockTipbar`, `SetFilterDeceiveInfo_old`, `SetPopTipForFilterAdv_BB_old`, `SetPopTipForFilterAdv_old`, `SetShowIEPlusIcon`, `SetStatFunc`, `SetState`, `SetTipForFilterDeceive_old`, `UnInit`

### `safemon/HipsLogCenter.dll` (x86, 27 导出)
- `GetPreventListCount`, `IsSupport_ADLogRDP`, `IsSupport_ADLogSQL`, `IsSupport_DownLoadRecord`, `IsSupport_HipsRecord`, `IsSupport_NetShare`, `IsSupport_PreventLog`, `IsSupport_PriRecord`, `IsSupport_SysLogClear`, `IsSupport_SysLogHit`, `IsSupport_SysLogRDPLogin`, `IsSupport_SysLogSMBLogin`, `IsSupport_SysLogSQL`, `IsSupport_TrustLog`, `Show_ADLogRDP`, `Show_ADLogSQL`, `Show_DownLoadRecord`, `Show_HipsRecord`, `Show_NetShare`, `Show_PreventLog`, `Show_PriRecord`, `Show_SysLogClear`, `Show_SysLogHit`, `Show_SysLogRDPLogin`, `Show_SysLogSMBLogin`, `Show_SysLogSQL`, `Show_TrustLog`

### `safemon/360safemonpro.tpi` (x86, 26 导出)
- `BindTtl`, `CreatePlugin`, `CreateTrayClient`, `GenBlockInjectProcsDat`, `GenRandomSCEHardErrorCode`, `GetDLRecords`, `GetJavaFileStackInfo`, `GetJavaStackInfo`, `GetLastRunningLnk`, `HandlerWarrantyInfo`, `HandlerWarrantyInfo2`, `IsBrowserInPrivateState`, `NotifyDlGuard`, `NotifyProcessProc`, `NotifyProcessProc2`, `NotifyProcessProcEx`, `NotifyProcessProci18n`, `ReleaseWarrantyInfo`, `RepairLogic`, `SimulateCopyData`, `SmDownloadFileIsReported`, `TryUpdateModule`, `UncrtIf`, `gcsm`, `gzpmsg`, `gzptl`

### `safemon/360UDiskGuard.dll` (x86, 26 导出)
- `CreateJunctionPoint`, `CreateJunctionPointTry`, `DeleteJunctionPoint`, `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `EjectVolume`, `EjectVolumeForce`, `GetDriveDevName`, `GetModifiedDoc`, `GetMonVersion`, `GetVolumeCollection`, `GetVolumeSpace`, `HideDeskBandXP`, `HideDeskBandXPLater`, `InstallUsbGuard`, `IsSideBarOpen`, `IsUPanWritable`, `IsUsbDisk`, `IsVolumeUsed`, `IsWriteProtected`, `ResetJunctionPoint`, `ShowDeskBand`, `ShowDeskBandWeak`, `ShowDeskBandXPLater`

### `safemon/360UDiskGuard64.dll` (x64, 26 导出)
- `CreateJunctionPoint`, `CreateJunctionPointTry`, `DeleteJunctionPoint`, `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `EjectVolume`, `EjectVolumeForce`, `GetDriveDevName`, `GetModifiedDoc`, `GetMonVersion`, `GetVolumeCollection`, `GetVolumeSpace`, `HideDeskBandXP`, `HideDeskBandXPLater`, `InstallUsbGuard`, `IsSideBarOpen`, `IsUPanWritable`, `IsUsbDisk`, `IsVolumeUsed`, `IsWriteProtected`, `ResetJunctionPoint`, `ShowDeskBand`, `ShowDeskBandWeak`, `ShowDeskBandXPLater`

### `safemon/BrowserFix.dll` (x86, 26 导出)
- `CreateExamineInterface`, `CreatePluginCleanerPageEntry`, `CreatePluginRestorePage`, `CreateRestorePage`, `CreateSiteUIPage`, `CreateSystemFixPage`, `CreateSystemFixStartUIPage`, `CreateSystemFixStartUIPage2`, `FilterDllMsg`, `FixBrowser`, `FixBrowserStatus`, `GetBrCount`, `GetHomePage`, `GetHomePageStatus`, `IsSupported`, `IsSystemFixNewUIPage`, `Load360WdMain`, `ProcessDllIdle`, `QueryBrowserStatus`, `ScanBrowser`, `SetHomePageStatus`, `ShowFixBrowserDlg`, `ShowFixIeDlg`, `ShowHomePageProDlg`, `ShowLockHomePageDlg`, `ShowStartPageSetingDlg`

### `safemon/360AntiSteal.dll` (x86, 23 导出)
- `fcapi_begin_transfer`, `fcapi_clear_rules`, `fcapi_close`, `fcapi_close_monitor`, `fcapi_end_transfer`, `fcapi_get_cache`, `fcapi_get_cache_number`, `fcapi_install`, `fcapi_onekey_close`, `fcapi_onekey_open`, `fcapi_open`, `fcapi_open_monitor`, `fcapi_pop_rules`, `fcapi_push_rules`, `fcapi_reg_transfer_data_callback`, `fcapi_set_cache_size`, `fcapi_set_policy`, `fcapi_startup`, `fcapi_stop`, `fcapi_transfering`, `fcapi_uninstall`, `fcapi_unwork`, `fcapi_work`

### `safemon/360procmon.dll` (x86, 17 导出)
- `AddRuleTFW`, `BoxRule2HipsRule`, `BuildAndLoadRuleFile`, `CreateTrayClient`, `FixRegSrv`, `GetLogFileName`, `GetRuleInfo`, `InstallCall`, `Is360SafeUnique`, `IsSelfProtectOn`, `OffSelfProtect`, `OffSelfProtectEx`, `ReloadSelfProtectRule`, `SDRule2HipsRule`, `SectxRule2HipsRule`, `UninstallCall`, `VtIsWin64`

### `safemon/360compro.dll` (x86, 16 导出)
- `CalcV3Param_RunOnce`, `CreateFireWallState`, `CreateFireWallState2`, `CreateFireWallState3`, `CreateFireWallState4`, `CreateFireWallStateQuick`, `CreateFireWallStateQuick2`, `CreateFireWallStateQuick3`, `CreatePluginFactory`, `CreateTrayClient`, `DeleteV3ParamItem`, `GetDeviceProState`, `GetV3ParamInfo`, `NewCreatePlugin`, `SetAntiVirusCheckFlag`, `SetDeviceProState`

### `safemon/360compro64.dll` (x64, 16 导出)
- `CalcV3Param_RunOnce`, `CreateFireWallState`, `CreateFireWallState2`, `CreateFireWallState3`, `CreateFireWallState4`, `CreateFireWallStateQuick`, `CreateFireWallStateQuick2`, `CreateFireWallStateQuick3`, `CreatePluginFactory`, `CreateTrayClient`, `DeleteV3ParamItem`, `GetDeviceProState`, `GetV3ParamInfo`, `NewCreatePlugin`, `SetAntiVirusCheckFlag`, `SetDeviceProState`

### `safemon/Netm.tpi` (x86, 14 导出)
- `CheckSupportNewTeen`, `CreateEncryptFactory`, `CreateTrayClient`, `CreateUrlFactory`, `GetCloudTipLogInterface`, `GetPerformanceMode`, `IdleExitNotifyProc`, `IdleNotifyProc`, `IsJsqEnabled`, `IsShowJsqTrayMenu`, `IsSupportEduMode`, `SetJsqEnabled`, `SetPerformanceMode`, `ShowJsq`

### `safemon/360TrayLive.dll` (x86, 12 导出)
- `CreateTrayClient`, `IdleExitNotifyProc`, `IdleNotifyProc`, `Is3GMode`, `Is3GModeNotUpdate`, `IsForceUpdateLibs`, `IsGameMode`, `IsGameModeNotUpdate`, `IsHaveFullScreenApp`, `Set3GModeNotUpdate`, `SetForceUpdateLibsFlag`, `SetGameModeNotUpdate`

### `safemon/wdui2.dll` (x86, 12 导出)
- `WDCreateSeLnkTip`, `WDCreateSoLnk`, `WDCreateSoLnkV2`, `WDCreateUrlWindow`, `WDCreateWindow`, `WDDestroyWindow`, `WDDrawWindow`, `WDGetExitCode`, `WDGetLnkSoState`, `WDGetUrlRGY`, `WDInitDraw`, `WDShowSoLnkTip`

### `safemon/360webpro.dll` (x86, 11 导出)
- `CreateNetmonClient`, `DllRegisterServer`, `DllUnregisterServer`, `DrvUpdateNeedRestart`, `GetArpState`, `IsDrvInstall`, `IsNeedLoad`, `IsNeedUpdate`, `IsShowUnInstArpMsg`, `IsSupported`, `SetArpState`

### `safemon/safemon64.dll` (x64, 11 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `Initialize`, `IsTraystupidRealRunning`, `safemon_115`, `safemon_117`, `safemon_118`, `safemon_119`, `safemoninit`

### `safemon/SelfProtectAPI2.dll` (x86, 11 导出)
- `APICreateObjectSelfProc`, `APIDisableSendInput`, `APIEnableSendInput`, `APILeaveSendInputControl`, `APIQueryCmrStreamStatus`, `APISetCmrStreamStatus`, `APISetTrayService`, `APIStartCmrMonitor`, `APIStartSendInputControl`, `APIStopCmrMonitor`, `IsWin10FakeDrvFWStat`

### `safemon/urlproc.dll` (x86, 9 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `QH360UrlLibAttachObject`, `QH360UrlLibAttachObjectV2`, `QH360UrlLibCreateResultParser`, `StartCleaner`, `StopCleaner`

### `safemon/iNetSafe64.dll` (x64, 8 导出)
- `DeRegisterMonitor`, `InitMonitor`, `Initialize`, `RegisterMonitor`, `RegisterUrlQueryCallBack`, `SetMonitorFilter`, `StartMonitor`, `StopMonitor`

### `safemon/ntvbld.dll` (x86, 8 导出)
- `Initialize`, `Initialize0`, `SE_DllLoaded`, `SE_DllUnloaded`, `SE_GetProcAddress`, `SE_InstallAfterInit`, `SE_InstallBeforeInit`, `SE_ProcessDying`

### `safemon/safehmpg.dll` (x86, 8 导出)
- `SafehmpgHelper`, `SafehmpgHelper001`, `SafehmpgHelper002`, `SafehmpgHelper003`, `SafehmpgHelper004`, `SafehmpgHelper005`, `SafehmpgHelper006`, `SafehmpgHelper007`

### `safemon/safemonhlp.dll` (x86, 8 导出)
- `init`, `mict`, `mlcbgetversion`, `mlcbproc`, `qhadproc`, `tpicallback`, `tpicallback2`, `tpicallback3`

### `safemon/360dfsopt.tpi` (x86, 7 导出)
- `CreateTrayClient`, `EAInstUpdate`, `GetProtectState`, `SetProtectState`, `Uninstall`, `UninstallQpesv`, `UpdateQueryTime`

### `safemon/360hipspopwnd.dll` (x86, 7 导出)
- `CreateTrayClient`, `Hips_CreateNotifyWnd`, `IsSupportNewIELock`, `IsSupportWndType`, `PreInit`, `RegClawPopWnd`, `Uninstall`

### `safemon/iNetSafe.dll` (x86, 7 导出)
- `DeRegisterMonitor`, `InitMonitor`, `Initialize`, `RegisterMonitor`, `SetMonitorFilter`, `StartMonitor`, `StopMonitor`

### `safemon/libzdtp.dll` (x86, 7 导出)
- `Bpp`, `Getmods`, `Hpp`, `Initialize`, `InitializeEx`, `Jpp`, `Npps`

### `safemon/libzdtp64.dll` (x64, 7 导出)
- `Bpp`, `Getmodl`, `Hpp`, `Initialize`, `InitializeEx`, `Jpp`, `Nppl`

### `safemon/360TrayLogin.tpi` (x86, 6 导出)
- `CreateTrayClient`, `EncryptBuffer`, `FreeEncryptedBuffer`, `FreeMiniEnvBuf`, `GetMiniEnvState`, `GetMiniEnvStateEncrypted`

### `safemon/360TrayMenu.dll` (x86, 6 导出)
- `CreateTrayClient`, `DoJudgePwdRight`, `DoJudgePwdRight2`, `DoJudgePwdRight3`, `_DoJudgePwdRight`, `_UpdatePwdPolicy`

### `safemon/DlProc.dll` (x86, 6 导出)
- `CreateDLProc`, `InitFlashScan`, `ScanFlashFile`, `engdisp`, `grvit`, `setattr`

### `safemon/imhelper.dll` (x86, 6 导出)
- `ImSafeHelper001`, `ImSafeHelper002`, `ImSafeHelper003`, `ImSafeHelper005`, `ImSafeHelper006`, `ImSafeHelper007`

### `safemon/obTracer.tpi` (x86, 6 导出)
- `Ahl`, `CreateTrayClient`, `DeclareRunInService`, `GetPslState`, `Shl`, `ShlU`

### `safemon/SMLStarter.tpi` (x86, 6 导出)
- `CreateTrayClient`, `IdleExitNotifyProc`, `IdleNotifyProc`, `JudgeAntiVirusSoftStatus`, `RevertFileTypeShell`, `SafeUninstall`

### `safemon/DiagScanTips.tpi` (x86, 5 导出)
- `CreatePluginCollection`, `CreateTrayClient`, `IdleExitNotifyProc`, `IdleNotifyProc`, `TpiInstall`

### `safemon/libgravity.dll` (x86, 5 导出)
- `GetHandleVerifier`, `IsSandboxedProcess`, `envcfg`, `envinit`, `ver`

### `safemon/safe505.dll` (x86, 5 导出)
- `LaunchExecute`, `Recuse360Tray`, `do505`, `do505ex`, `do505rd`

### `safemon/wdsandbox.exe` (x86, 5 导出)
- `_lock@8`, `_pscdp@8`, `_pscdpthunk2@8`, `_pscdpthunk@20`, `_unlock@8`

### `safemon/wdtHelper.dll` (x86, 5 导出)
- `InitializeInitializeInitializeInitializeInitializeInitializeInitializelstbx`, `Msxlsi`, `Run`, `SafeInitialize`, `SetSendLogFunction`

### `safemon/360AntiHijack.tpi` (x86, 4 导出)
- `CreateNetControl`, `CreateTrayClient`, `CreateWebControl`, `CreateWebControl2`

### `safemon/BootLeakFixer.tpi` (x86, 4 导出)
- `CreateEvtPubChannel`, `CreateEvtRecordMgr`, `CreateTrayClient`, `SyncTime`

### `safemon/d2dkd.dll` (x86, 4 导出)
- `ExportCleanUp`, `ExportRestore`, `Initialize`, `Uninitialize`

### `safemon/DsTpi.tpi` (x86, 4 导出)
- `CreateTrayClient`, `IdleExitNotifyExtroProc`, `IdleExitNotifyProc`, `IdleNotifyProc`

### `safemon/Ntvbld64.dll` (x64, 4 导出)
- `InitValue`, `InitValue_Ex`, `Initialize`, `NtvbldHelper`

### `safemon/SDPlugin/AdPopWnd.dll` (x86, 4 导出)
- `CreatePlugin`, `PopupIsEnable`, `QueryInterface`, `RevokeRuleID`

### `safemon/360TrayStub.dll` (x86, 3 导出)
- `CreateInstance`, `Initialize`, `Uninitialize`

### `safemon/ieplus64.dll` (x64, 3 导出)
- `Init`, `IsSupport`, `UnInit`

### `safemon/QseCore.dll` (x86, 3 导出)
- `GetQseCoreInterface`, `GetQseCoreVersion`, `GetSafeRouteInterface`

### `safemon/safehmpg64.dll` (x64, 3 导出)
- `SafehmpgHelper`, `SafehmpgHelper001`, `SafehmpgHelper007`

### `safemon/swverify32.dll` (x86, 3 导出)
- `Has360SignExA`, `Has360SignExW`, `TestContext`

### `safemon/zeropmgr.dll` (x86, 3 导出)
- `Destory_ZeropMgr`, `IsSupport_ZeropMgr`, `Show_ZeropMgr`

### `safemon/360EPSVH.dll` (x86, 2 导出)
- `GetHookAPIs`, `NotifyShims`

### `safemon/360EPSVH64.dll` (x64, 2 导出)
- `GetHookAPIs`, `NotifyShims`

### `safemon/360GuardBase.dll` (x86, 2 导出)
- `GB_SetPayInsure`, `GetEntryInterface`

### `safemon/360scovec.dll` (x86, 2 导出)
- `DoWork`, `Initialize`

### `safemon/360scovec64.dll` (x64, 2 导出)
- `DoWork`, `Initialize`

### `safemon/360trayexit.dll` (x86, 2 导出)
- `ShowExitDlg`, `ShowExitDlgByNetPayFlag`

### `safemon/360xpfix.dll` (x86, 2 导出)
- `IsXPFixAllOpen`, `IsXPFixSupport`

### `safemon/360zipc.dll` (x86, 2 导出)
- `CreateNZPObject`, `DeleteNZPObject`

### `safemon/EPSVHRule.dll` (x86, 2 导出)
- `CreateProtectInstance`, `Uninstall`

### `safemon/safewrapper.dll` (x64, 2 导出)
- `Initialize`, `Initialize2`

### `safemon/safewrapper32.dll` (x86, 2 导出)
- `Initialize`, `Initialize0`

### `safemon/swverify64.dll` (x64, 2 导出)
- `Has360SignExA`, `Has360SignExW`

### `safemon/UDiskScanEngine.dll` (x86, 2 导出)
- `CreateUDiskScanEngine`, `DestroyUDiskScanEngine`

### `safemon/WdHPFileSafe.dll` (x86, 2 导出)
- `CreateHPCtrl`, `GetHPHistory`

### `safemon/WDRecord.dll` (x86, 2 导出)
- `GetDataBase`, `GetWDDataBase`

### `safemon/360bsmon.tpi` (x86, 1 导出)
- `CreateTrayClient`

### `safemon/360GPMon.dll` (x86, 1 导出)
- `Initialize`

### `safemon/360GPMon64.dll` (x64, 1 导出)
- `Initialize`

### `safemon/360SafeCamera.tpi` (x86, 1 导出)
- `CreateTrayClient`

### `safemon/AdPopBlocker.tpi` (x86, 1 导出)
- `CreateTrayClient`

### `safemon/AutoCleanTrash.tpi` (x86, 1 导出)
- `CreateTrayClient`

### `safemon/chromesafe.dll` (x86, 1 导出)
- `Initialize`

### `safemon/chromesafe64.dll` (x64, 1 导出)
- `Initialize`

### `safemon/netmon.tpi` (x86, 1 导出)
- `CreateTrayClient`

### `safemon/probe.dll` (x86, 1 导出)
- `start`

### `safemon/qroscfg.dll` (x86, 1 导出)
- `ConvertConfig`

### `safemon/qutmvd.tpi` (x86, 1 导出)
- `CreateTrayClient`

### `safemon/uniconft.dll` (x86, 1 导出)
- `l`

### `safemon/uniconft64.dll` (x64, 1 导出)
- `l`

### `safemon/wdefence.dll` (x86, 1 导出)
- `Execute`

### `safemon/wdexhelper.dll` (x86, 1 导出)
- `SetValue`

### `safemon/wdexhelperx64.dll` (x64, 1 导出)
- `SetValue`

### `safemon/wdui3.dll` (x86, 1 导出)
- `WDUICreateObject`

### `safemon/wdzerop.dll` (x86, 1 导出)
- `GetZeropList`

### `safemon/webprotect.dll` (x86, 1 导出)
- `LockHomePage`

## 工具与扩展(Utils/)  （28 模块 / 199 导出）
### `Utils/360SafeChecker.dll` (x86, 36 导出)
- `CheckHpPrinterAndPopDlg`, `CheckMaybeBlueScreen`, `CreateNotifyDlg`, `CreateSiteUIPage`, `CreateTrustZoneNotifyDlg`, `DnsGuardderOperation`, `GetCurrentPageID`, `GetEmpStage`, `GetNotifyUpdateSpyerDlgHWND`, `GetNotifyUpdateSpyerDlgHWND2`, `InitPreCreateUI`, `IsEmpHoding`, `IsEngSupportEmp`, `IsFeatureSupport`, `IsOffLineSpyerLibTooOld`, `IsSupportUploadZoneUI`, `NotifyCallTd`, `NotifyInvokeSuperKiller`, `NotifyRBPWROFF`, `NotifyScanArk`, `NotifyScanArk2`, `OpenTrustDlg`, `OperateScanLog`, `PreExitProcess`, `ProcessDS`, `RunnedTDWS`, `SEHS`, `SafeUpdateInterface`, `ScanOFFPWR`, `SendMainCommand`, `ShowSpyerLibUpdateDlg`, `SkinMsgBox`, `SkinMsgBoxNew`, `TrustZone_Destroy`, `TrustZone_SHOWFUNC`, `WifiCheckUIOperation`

### `Utils/DrvmgrCore.dll` (x86, 24 导出)
- `CompressFileToZip`, `CompressFileToZipWithPath`, `Create360BackupMgrInterface`, `Create360BackupMgrInterface2`, `Create360ScanMgrInterface`, `CreateCloudBackupMgrInterface`, `CreateInstallAndUnstallManager`, `CreateScanAndUploadMgrInterface`, `DrvInterfaceManger_Query`, `GetDevTypeDisplayName`, `GetDeviceStatusFullInfo`, `GetDeviceStatusInfo`, `GetGlobalInfo`, `GetGlobalInfo_2`, `GetMidString`, `InstallDriver`, `InstallDriver2`, `InstallNetDriver`, `SharedConfigMgr`, `UninstallAmdDisplay`, `UninstallDriver`, `UninstallIntelDisplay`, `UninstallNvidiaDisplay`, `_GetDevType`

### `Utils/AdvToolsEx.dll` (x86, 14 导出)
- `ChangeControlTheme`, `CreateBottomUI`, `CreateToolInstaller`, `ExportToolUpdateByFlag`, `ExportToolUpdateByRect`, `ExternalAirInstallTool`, `ExternalAirUninstallTool`, `ExternalAirUninstallToolEx`, `ExternalIsToolInstall`, `ExternalToolUpdateTip`, `GetAdvToolEntry`, `GetAdvToolPage`, `GetSearchMgr`, `InitPreCreateUI`

### `Utils/shell360ext.dll` (x86, 14 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer`, `GetContextMenuCode`, `GetContextMenuState`, `GetNamiAIContextMenuState`, `GetQingLiLaJiContextMenuState`, `IsShowQingLiLaJiContextMenuState`, `SetContextMenuCode`, `SetContextMenuState`, `SetNamiAIContextMenuState`, `SetQingLiLaJiContextMenuState`

### `Utils/shell360ext64.dll` (x64, 14 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer`, `GetContextMenuCode`, `GetContextMenuState`, `GetNamiAIContextMenuState`, `GetQingLiLaJiContextMenuState`, `IsShowQingLiLaJiContextMenuState`, `SetContextMenuCode`, `SetContextMenuState`, `SetNamiAIContextMenuState`, `SetQingLiLaJiContextMenuState`

### `Utils/360Protect.dll` (x86, 13 导出)
- `ChangeControlTheme`, `CreatePromoteToolPage`, `CreatePromoteUIPage`, `CreateSiteUIPage`, `CreateSpeedOptToolPage`, `CreateV13ResultToolPage`, `GetState`, `IsSupport`, `IsUISupportNewSpeedOpt`, `IsUISupportV13Result`, `OpenNewPage`, `SetState`, `ShowResultBottomPromotePage`

### `Utils/analyst.dll` (x64, 10 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer`, `InitializeServer`, `InstallLegacyHookW`, `Restore`, `UninitializeServer`, `startAnalyst`

### `Utils/360SysRepairUI.dll` (x86, 9 导出)
- `CreateShutDownFix`, `CreateSiteUIPage`, `CreateSiteUIPage2`, `Destroy_LeakMgr`, `DriverRebootInstall`, `InitPreCreateUI`, `IsSupport_LeakMgr`, `NewCreatePlugin`, `Show_LeakMgr`

### `Utils/360seclogon/360DBGuard.dll` (x86, 9 导出)
- `FilterCallBack`, `GetProtectRule`, `GetState`, `IsIpInWhitelist`, `IsSupport`, `OpenNewPage`, `ResetRDPFilter`, `SetState`, `SetWhiteJsonData`

### `Utils/lsinst.dll` (x86, 7 导出)
- `ExtractAllResources`, `ExtractResource`, `GetResourceCount`, `GetResourceName`, `GetResourceSize`, `InitializeResources`, `ResourceExists`

### `Utils/ModuleUpd.dll` (x86, 7 导出)
- `CreateModuleUpdate`, `Init`, `QueryModuleUpdateStatus`, `SetModuleUpdateOption`, `StartModuleUpdate`, `StopModuleUpdate`, `Uninit`

### `Utils/SiteUIProxy.dll` (x86, 6 导出)
- `Get360Customizine`, `GetChangeSkinManager`, `GetMiniUICompatible`, `GetSiteUIProxy`, `GetSkinImage`, `GetSmartInitializer`

### `Utils/Immune/HotfixCommon.dll` (x86, 6 导出)
- `EvaluateHotpatchState`, `EvaluateRDPHotpatchWorking`, `RunTargetHotpatch`, `RunTargetHotpatchUninstall`, `RunTargetRDPHotpatch`, `RunTargetRDPHotpatchUninstall`

### `Utils/Immune/HotfixCommon64.dll` (x64, 6 导出)
- `EvaluateHotpatchState`, `EvaluateRDPHotpatchWorking`, `RunTargetHotpatch`, `RunTargetHotpatchUninstall`, `RunTargetRDPHotpatch`, `RunTargetRDPHotpatchUninstall`

### `Utils/360ExamineUIEx.dll` (x86, 5 导出)
- `CreateSearchSite`, `CreateSiteUIPage`, `OnSmartGuideFinish`, `SetSmartGuideFlag`, `Uninstall`

### `Utils/360ExpLogin.dll` (x86, 3 导出)
- `Create360LoginMgr`, `CreateExpLogin`, `InstallSafeidPackage`

### `Utils/360NetSafeUI.dll` (x86, 3 导出)
- `CreateSiteUIPage`, `CreateSiteUIPage2`, `CreateSiteUIPage3`

### `Utils/7zWrapper.dll` (x86, 2 导出)
- `ExtractFileToDir`, `ExtractMemToDir`

### `Utils/DownloadMgr.dll` (x86, 2 导出)
- `Create360DownloadMgrInterface`, `Create360DownloadMgrInterface2`

### `Utils/360ExpClient.dll` (x86, 1 导出)
- `CreateExpClient`

### `Utils/360ExpData.dll` (x86, 1 导出)
- `CreateShareData`

### `Utils/AntiTrack.dll` (x86, 1 导出)
- `CreateAntiTrack`

### `Utils/AntiTrack64.dll` (x64, 1 导出)
- `CreateAntiTrack`

### `Utils/DnsOpt.dll` (x86, 1 导出)
- `CreateDnsOpt`

### `Utils/Hamster.dll` (x86, 1 导出)
- `HamsterCreateObject`

### `Utils/LeakFixHelper.dll` (x86, 1 导出)
- `DoHook`

### `Utils/LeakFixHelper64.dll` (x64, 1 导出)
- `DoHook`

### `Utils/ExaminePlugins/CheckAutorun2.dll` (x86, 1 导出)
- `CreatePlugin`

## 扫描引擎·AVE(特征)  （2 模块 / 26 导出）
### `deepscan/AVE/AVEI.dll` (x86, 19 导出)
- `AveQueryResult`, `CalcMicroFeatureA`, `CalcMicroFeatureW`, `CloseScanner`, `CreateScanner`, `CreateScannerEx`, `GetFileProp`, `KillIStream`, `Scan`, `ScanFileEnum`, `ScanFileEnumW`, `ScanIStream`, `ScanMem`, `ScanProc`, `ScanProc64`, `ScanProc64Ex`, `ScanProcEx`, `ScanW`, `SetScannerConfig`

### `deepscan/AVE/AVEngine.dll` (x86, 7 导出)
- `AveInitialize`, `BAPIInitialize`, `CalcDotNetIndexA`, `CalcDotNetIndexW`, `ClearEnviroment`, `CreateEnviroment`, `GetClassObject`

## 扫描引擎·QVM(Bole)  （1 模块 / 6 导出）
### `deepscan/QVM/360QVM.dll` (x86, 6 导出)
- `BoleFeaturesInitialize`, `BoleGetVersion`, `BoleInitialize`, `ClearEnviroment`, `CreateEnviroment`, `GetClassObject`

## 扫描引擎·qex(文档/格式)  （1 模块 / 10 导出）
### `deepscan/qex/qex.dll` (x86, 10 导出)
- `CreateInstance`, `QEXCreateInstance`, `QexResourceExportsInit`, `QexScanExportsInit`, `TypeEnum2Descript`, `TypeString2Descript`, `testole_close_ole`, `testole_extract_index`, `testole_get_count`, `testole_open_ole`

## 根目录模块  （29 模块 / 328 导出）
### `LiveUpd360.dll` (x86, 38 导出)
- `PPClose`, `PPCloseHandle`, `PPDownload`, `PPGetConfig`, `PPInit`, `PPQueryTask`, `PPQueryTaskEx`, `PPRemoveTask`, `PPRestart`, `PPSetConfig`, `PPStartTask`, `PPStartTaskEx`, `PPStopSeed`, `PPStopTask`, `StartLan`, `StopLan`, `_EnableP2P`, `_GetLanupTasks`, `_GetProductLst`, `_GetTasks`, `_IsStopped`, `_P2SPCancelCheckProxy`, `_P2SPCheckProxy`, `_P2SPCheckProxyEx`, `_P2SPSetOption`, `_P2SPUpdateRegInfo`, `_PPQueryIPPort`, `_PPQueryProduct`, `_PPQueryTask2`, `_PPQueryTask3`, `_PPSetLocalLog`, `_Run`, `_SetKeep`, `_SetKeepEx`, `_SetLocalLog`, `_StartRun`, `_StopRun`, `__PPSetModulePath2`

### `360Common.dll` (x86, 36 导出)
- `CheckConflict`, `CheckUpdate`, `Create360FireWareStateFunction`, `Create360FireWareStateFunction2`, `Get360CommonInstance`, `Get360DownloadPath`, `Get360ProductHistoryManager`, `Get360SafeUEState`, `GetCompuateAidStatus`, `GetDpiScaleParam`, `GetExcludeChecker`, `GetFireWallState`, `GetIAdMgr`, `GetMedalWallStatus`, `GetMobileMgrShowStatus`, `GetMobileMgrStatus`, `GetModularizeManager`, `GetSearchDesktopStatus`, `GetSoftMgrStatus`, `Has360MsSign`, `IsInstallInNetBar`, `IsShowComputeAid`, `IsShowMedalWall`, `IsShowMobileMgr`, `IsShowMobileMgrSet`, `IsShowSearchDesktop`, `IsShowSoftMgr`, `ModularizeAfterSetup`, `SafeSupportDpi`, `Set360SafeUEState`, `SetCompuateAidStatus`, `SetMedalWallStatus`, `SetMobileMgrShowStatus`, `SetMobileMgrStatus`, `SetSearchDesktopStatus`, `SetSoftMgrStatus`

### `360net.dll` (x86, 25 导出)
- `HttpCancel`, `HttpCreateDownloadObj`, `HttpDeleteDownloadObj`, `HttpDownload`, `HttpDownloadExA`, `HttpDownloadExW`, `HttpGetAllPeer`, `HttpGetConnectState`, `HttpGetContentLength`, `HttpGetCurrentSpeed`, `HttpGetLastError`, `HttpGetLastErrorA`, `HttpGetLastErrorW`, `HttpGetMD5`, `HttpGetReceivedLength`, `HttpGetResumedLength`, `HttpGetState`, `HttpGetStateA`, `HttpGetStateW`, `HttpInitDownPara`, `HttpResetAll`, `HttpSetOption`, `HttpWait`, `InitHttp`, `UnInitHttp`

### `sites.dll` (x86, 24 导出)
- `CreateMemoryFile`, `CreateShadowEdgeInstance`, `CreateXMLDOMDocument`, `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `GetFactory`, `GetFileDataFromStorage`, `GetFileLengthFromStorage`, `GetFileLengthFromStorageEx`, `GetFontCharset`, `GetMainThreadClub`, `GetPerformanceEvaluation`, `IsDesignerMode`, `SetDefaultResourceInfo`, `SetDesignerMode`, `SetFontCharset`, `SmartDisableIME`, `UninitMainThreadClub`, `scale`, `scale_font`, `set_dpi_flag`, `set_dpi_strategy`

### `sites64.dll` (x64, 24 导出)
- `CreateMemoryFile`, `CreateShadowEdgeInstance`, `CreateXMLDOMDocument`, `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `GetFactory`, `GetFileDataFromStorage`, `GetFileLengthFromStorage`, `GetFileLengthFromStorageEx`, `GetFontCharset`, `GetMainThreadClub`, `GetPerformanceEvaluation`, `IsDesignerMode`, `SetDefaultResourceInfo`, `SetDesignerMode`, `SetFontCharset`, `SmartDisableIME`, `UninitMainThreadClub`, `scale`, `scale_font`, `set_dpi_flag`, `set_dpi_strategy`

### `AntiAdwa.dll` (x86, 23 导出)
- `AdLib_Init`, `AdLib_InitEx`, `AntiWare_CombinationSafeFile`, `AntiWare_CreateHPControl`, `AntiWare_CreatePluginControl`, `AntiWare_CreatePluginControl2`, `AntiWare_SimpleAdwareScan`, `AntiWare_SimpleControl`, `CbSectionRestore`, `CheckHomePage`, `Control_RunDLL`, `CreateAntiInterFace`, `CreatePluginFactory`, `CreatePluginFactory2`, `CreateQuarantObjectFactory`, `CreateTrustListEntry`, `DllRegisterServer`, `DllUnregisterServer`, `KillAdware`, `NewCreatePlugin`, `RemoveAllAdware`, `SetDeepscanPath`, `_CreatePluginFactoryEx@4`

### `360P2SP.dll` (x86, 20 导出)
- `CancelCheckProxy`, `CheckProxy`, `CheckProxyEx`, `CreateP2SPTask`, `GetFinishMessage`, `GetServerInfo`, `GetUploadInfo`, `Init`, `Login`, `QueryTask`, `QueryTask2`, `QueryTaskPeer`, `RemoveTask`, `SetConfigInfo`, `SetP2spOption`, `StartTask`, `StopSeed`, `StopTask`, `Uninit`, `UpdateRegInfo`

### `leakrepair.dll` (x86, 19 导出)
- `CanShowAIRestore`, `CanShowWindowsUpdate`, `CreatePlugin`, `CreatePluginFactory`, `DllCanUnloadNow`, `DllGetClassObject`, `GetAiRestore`, `GetCloudConfig`, `GetDownloadDirectory`, `GetInstallState`, `GetOfficeState`, `GetWindowUpdate`, `LeakRepairString`, `OnUninstall`, `OnUninstallI18n`, `SetAiRestore`, `SetDisplayLanguage`, `SetDownloadDirectory`, `SetWindowUpdate`

### `PDown.dll` (x86, 18 导出)
- `PPClose`, `PPCloseHandle`, `PPDownload`, `PPGetConfig`, `PPInit`, `PPInit2`, `PPQueryTask`, `PPQueryTaskEx`, `PPRemoveTask`, `PPRestart`, `PPSetConfig`, `PPSetOption`, `PPStartTask`, `PPStartTaskEx`, `PPStopSeed`, `PPStopTask`, `StartLan`, `StopLan`

### `360Ranges.dll` (x86, 11 导出)
- `PRSCreateRangesTask`, `PRSGetFinishMessage`, `PRSInit`, `PRSLogin`, `PRSQueryTask`, `PRSRemoveTask`, `PRSSetConfigInfo`, `PRSSetP2spOption`, `PRSStartTask`, `PRSStopTask`, `PRSUninit`

### `Safelive.dll` (x86, 11 导出)
- `BsPatchDiffA`, `BsPatchDiffW`, `ConnectUpdateServer`, `CreateUpdateServer`, `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `InitializeBAPI`, `SetBaseDirectory`, `UnInitializeBAPI`

### `360ver.dll` (x86, 10 导出)
- `Get360SafeVersion`, `Get360SafeVersionEx`, `GetExTitleA`, `GetExTitleW`, `GetSafeAirVersion`, `GetSafeSubTitle`, `GetVersionType`, `IsBetaVersion`, `IsEntVersion`, `VerifyFiles`

### `360Login.dll` (x86, 9 导出)
- `CreateInterface`, `CreateLonginStubW`, `DestroyLoginStubW`, `InitLoginStubW`, `LoginGetModuleW`, `LoginStubDownloadDataW`, `LoginStubGetInfoStr`, `LoginStubUploadDataW`, `UnInitLoginStubW`

### `360NetBase.dll` (x86, 8 导出)
- `FreeLocalInterfaceBuffer`, `GetFilterActionByUrl`, `GetNetProbe`, `GetSelectedRandomProxy`, `InitLibs`, `QueryLocalInterface`, `SetNetProbe`, `SmartGetIp`

### `360Base.dll` (x86, 6 导出)
- `BaseCheckProductType`, `BaseGetProductPath`, `BaseGetProductRegRoot`, `BaseIsOnlySha1Sign`, `CreateObject`, `InitLibs`

### `CrashReport.dll` (x86, 6 导出)
- `?RaiseException@@YAXXZ`, `AutoSend`, `CrSetADStop`, `Initialize`, `Initialize2`, `OnExiting`

### `360NetUL.dll` (x86, 5 导出)
- `HttpInit`, `HttpUninit`, `zlib_compress`, `zlib_compressBound`, `zlib_uncompress`

### `360UCenter.dll` (x86, 5 导出)
- `CreateSiteUIPage`, `GetShowAILink`, `Launch360UserCenter`, `Login360UserCenter`, `SetShowAILink`

### `360Restore.dll` (x86, 4 导出)
- `IsSupportRestoreCmd`, `IsSupportRestoreUI`, `RestoreUI_Destroy`, `RestoreUI_SHOWFUNC`

### `dynlbase.dll` (x86, 4 导出)
- `Register`, `RegisterFast_First`, `RegisterFast_Second`, `RegisterOnlyBase`

### `FastAnimation.dll` (x86, 4 导出)
- `CeateApngImage`, `CeateFastAnimationCtrl`, `CeateFastAnimationCtrlEx`, `CeateRlottieImage`

### `360ExamineEx.dll` (x86, 3 导出)
- `GetExamineInterface`, `PreExitProcess`, `SetExamineItemHealth`

### `360Util.dll` (x86, 3 导出)
- `CreateObject`, `InitLibs`, `RegisterInstallTime`

### `BaseExamine.dll` (x86, 3 导出)
- `CreateCloudScanPlugin`, `CreateLeakRepairPlugin`, `CreatePromotePlugin`

### `360Verify.dll` (x86, 2 导出)
- `GetCIDA`, `GetCIDW`

### `CombineExt.dll` (x86, 2 导出)
- `CalcFileMD5`, `Combine`

### `dynlenv.dll` (x86, 2 导出)
- `get_lua_env_dispatch`, `get_lua_raw_dispatch`

### `EfiProc.dll` (x86, 2 导出)
- `EfiLoadBitmap`, `EfiUnloadBitmap`

### `360Conf.dll` (x86, 1 导出)
- `CreateObject`

## 深扫与云查(deepscan/)  （22 模块 / 968 导出）
### `deepscan/heavygate.dll` (x86, 243 导出，其中 sqlite3_* 243 条已折叠)

### `deepscan/qutmload.dll` (x86, 164 导出)
- `AddAntiInjectDllName`, `AddAntiInjectWhiteProcessName`, `AddBlackFileName`, `AddBlackProcessByPid`, `AddClientRule`, `AddClientRule2`, `AddExceptionRule`, `AddInjectBlockRule`, `AddInjectProcessName`, `AddInjectRule`, `AddKernelRule`, `AddProtectedFile`, `AddProtectedFile2`, `AddPsCreationExceptRule`, `AddRule`, `AddRule2`, `AddSpecialProtectedFile`, `AddTraceRule`, `AddWhiteFileName`, `AddWhiteProcessByPid`, `CleanAllPsCreationExceptRules`, `CleanInjectRule`, `CleanOpenFileRules`, `CleanupAllClientRules`, `CleanupAllRules`, `ClearAntiInjectRule`, `ClearBlackFileList`, `ClearBlackProcessList`, `ClearWhiteFileList`, `ClearWhiteProcessList`, `CloseClientSession`, `CloseReportDeviceDisable`, `CompressHistoryDatabase`, `ConfigObjectTraceRule`, `ConfigObjectTracer`, `ConvertNtName64`, `CreateClientHandle`, `CreateClientSession`, `CutHistoryDatabase`, `EnableLockCallBack`, `EnableProtectRule`, `EnableRemoteFileMonAddress`, `EnableReportTokenExtraDataEx`, `EnableRpcSvcVulnDetect`, `EnableRsMode`, `EncodeDComFilterData`, `EncodePipeFilterData`, `EncodeRpcTcpFilterData`, `EnumExistsCallbacks`, `FlushObjectTracerLogs`, `FlushObjectTracerLogs2`, `GetBootRuleData`, `GetClientSessionHandle`, `GetFileRemoteAddress`, `GetLastProcessCreationTime`, `GetObjectTracerConfig`, `GetRsModeState`, `InsertBrowserProcess`, `InsertProtectionModule`, `InsertProtectionProcess` …

### `deepscan/BAPI.dll` (x86, 143 导出)
- `AcquireArCk01`, `AcquireArCk02`, `AcquireArDs01`, `AcquireArDs02`, `AcquireArDs03`, `AcquireArDs04`, `AcquireArDs05`, `AcquireArLd01`, `AcquireArLd03`, `AcquireArMk01`, `AcquireArUf01`, `AcquireArUf02`, `AcquireArUf03`, `AcquireDispatch`, `AcquireMiniportStartIo`, `AcquireService`, `AcquireStartIoHook`, `BRegCloseKey`, `BRegCreateKey`, `BRegCreateKeyEx`, `BRegCreateKeyExW`, `BRegCreateKeyW`, `BRegDeleteKey`, `BRegDeleteKeyEx`, `BRegDeleteKeyExW`, `BRegDeleteKeyExW2`, `BRegDeleteKeyW`, `BRegDeleteValue`, `BRegDeleteValueW`, `BRegDeleteValueW2`, `BRegEnumKey`, `BRegEnumKeyEx`, `BRegEnumKeyExW`, `BRegEnumKeyW`, `BRegEnumValue`, `BRegEnumValueW`, `BRegOpenKey`, `BRegOpenKeyEx`, `BRegOpenKeyExW`, `BRegOpenKeyExW2`, `BRegOpenKeyW`, `BRegQueryValueEx`, `BRegQueryValueExW`, `BRegQueryValueExW2`, `BRegSetValueEx`, `BRegSetValueExW`, `BapiCreateToolhelp32Snapshot`, `BapiDriver32First`, `BapiDriver32Next`, `BapiModule32First`, `BapiModule32Next`, `BapiProcess32First`, `BapiProcess32Next`, `BfsSetFileApisToANSI`, `BfsSetFileApisToOEM`, `DllRegisterServer`, `DriverVersion`, `DsFileUnlock`, `DsGetFileLockType`, `DsSetTargetAccess` …

### `deepscan/cloudcom2.dll` (x86, 97 导出)
- `AVCacheClose`, `AVCacheCreate`, `AVCacheQuery`, `AVDeleteWhite`, `AVInsertWhite`, `AVNetQuery`, `AVNetQueryCancel`, `CacheClearOldData`, `CacheIsNeedClearOldData`, `CheckCloudServerState`, `CheckStreamTrust`, `Create360CommXClient`, `CreateObject`, `GetBest360Dns`, `GetDwordValue`, `GetFileTrustState`, `GetFileTrustStateEx`, `GetFileTrustStateEx2`, `GetFileTrustStateWithHandle`, `GetIspDns`, `GetStringValue`, `IsCahceTruested`, `IsSupportFeature`, `MisKillCheckDangerFileSignWhitList`, `MisKillClose`, `MisKillCreate`, `MisKillGetIsSystemFileName`, `MisKillJudgeWhite`, `MisKillJudgeWhiteEx`, `MisKillJudgeWhiteOnlyFile`, `QueryFileCancel`, `QueryFileClose`, `QueryFileCreate`, `QueryFilesEx`, `QueryFilesEx2`, `QueryFilesGetError`, `QueryFilesIsFileInXD`, `QueryFilesIsFileMD5InXD`, `QuerySetOption`, `RestoreDns`, `SetComOption`, `SetDns`, `SetVerifyFilePath`, `SigDestroy`, `SigInit`, `SigMatch`, `SigMatchCert`, `SmartAddRestoreFile`, `SmartCacheClearFileCache`, `SmartCacheClearOldData`, `SmartCacheClose`, `SmartCacheCreate`, `SmartCacheDelFiles`, `SmartCacheFileMonCallBack`, `SmartCacheFileMonCallBackEx`, `SmartCacheGetFLNPNumber`, `SmartCacheInsert`, `SmartCachePETime`, `SmartCacheQuery`, `SmartCacheQueryHips` …

### `deepscan/360Quarant.dll` (x86, 73 导出)
- `CreateQuarantFolder`, `CreateQuarantObject`, `DoCleanEPP`, `GetSectionItemCount`, `IsSupportFeature`, `Uninstall360SafeQuarant`, `UninstallQuarantItem`, `zip_close`, `zip_compression_method_supported`, `zip_discard`, `zip_encryption_method_supported`, `zip_error_code_system`, `zip_error_code_zip`, `zip_error_fini`, `zip_error_init`, `zip_error_init_with_code`, `zip_error_set`, `zip_error_set_from_source`, `zip_error_system_type`, `zip_error_to_data`, `zip_file_add`, `zip_file_attributes_init`, `zip_file_replace`, `zip_file_set_encryption`, `zip_get_name`, `zip_name_locate`, `zip_open`, `zip_open_from_source`, `zip_register_cancel_callback_with_state`, `zip_register_progress_callback`, `zip_register_progress_callback_with_state`, `zip_secure_random`, `zip_source_begin_write`, `zip_source_begin_write_cloning`, `zip_source_buffer`, `zip_source_buffer_create`, `zip_source_buffer_fragment`, `zip_source_buffer_fragment_create`, `zip_source_buffer_set_stream_callback`, `zip_source_close`, `zip_source_commit_write`, `zip_source_error`, `zip_source_file`, `zip_source_file_create`, `zip_source_free`, `zip_source_function`, `zip_source_function_create`, `zip_source_get_file_attributes`, `zip_source_is_seekable`, `zip_source_keep`, `zip_source_layered`, `zip_source_layered_create`, `zip_source_make_command_bitmap`, `zip_source_open`, `zip_source_pass_to_lower_layer`, `zip_source_read`, `zip_source_rollback_write`, `zip_source_seek`, `zip_source_seek_compute_offset`, `zip_source_seek_write` …

### `deepscan/jcloudscan.dll` (x86, 62 导出)
- `ApkFreeData`, `ApkGetApkAndroidManifestData`, `CloudQueryAppendItemArray`, `CloudQueryCalcBufferMfSha1AndFingerprint`, `CloudQueryCalcFileMfSha1AndFingerprintW`, `CloudQueryCancel`, `CloudQueryCreate`, `CloudQueryCreateItemArray`, `CloudQueryCreateQueryItem`, `CloudQueryDestroy`, `CloudQueryDestroyItemArray`, `CloudQueryDestroyQueryItem`, `CloudQueryGetItemArraySize`, `CloudQueryGetItemFileInfoApkInfoDownID`, `CloudQueryGetItemFileInfoApkInfoUploadFlag`, `CloudQueryGetItemFileInfoCanDelete`, `CloudQueryGetItemFileInfoCanReplace`, `CloudQueryGetItemFileInfoDesc`, `CloudQueryGetItemFileInfoExtInfo`, `CloudQueryGetItemFileInfoNetLevel`, `CloudQueryGetItemFileInfoQvmInfoDownID`, `CloudQueryGetItemFileInfoQvmInfoDownProperty`, `CloudQueryGetItemFileInfoQvmInfoLevel`, `CloudQueryGetItemFileInfoQvmInfoScore`, `CloudQueryGetItemFileInfoSoftClass`, `CloudQueryGetItemFileInfoTrojanName`, `CloudQueryGetItemFileNameAndSize`, `CloudQueryGetItemHandleFromItemArray`, `CloudQueryGetQueryError`, `CloudQueryNetQuery`, `CloudQuerySetCloudServer`, `CloudQuerySetItemCustomSha1AndCustomFingerPrint`, `CloudQuerySetItemCustomSha1WhenUseMemFile`, `CloudQuerySetItemFileInfoApkInfo`, `CloudQuerySetItemFileInfoApkInfoExtString`, `CloudQuerySetItemFileInfoApkInfoFileType`, `CloudQuerySetItemFileInfoApkInfoID`, `CloudQuerySetItemFileInfoFilePathAndSize`, `CloudQuerySetItemFileInfoQueryFlags`, `CloudQuerySetItemFileInfoQvmInfo`, `CloudQuerySetItemFileInfoQvmInfoBoleBuf`, `CloudQuerySetItemFileInfoQvmInfoExtString`, `CloudQuerySetItemFileInfoQvmInfoID`, `CloudQuerySetItemFileInfoReallocApkInfoOrQvmInfo`, `CloudQuerySetItemFileInfoScanType`, `CloudQuerySetItemQueryFlag`, `CloudQuerySetItemQueryType`, `CloudQuerySetItemUseFileOrMem`, `CloudQuerySetRequestHeaderOption`, `GetOrSetCurrentBaseUrl`, `Init360NetBaseDll`, `SoUploadCancel`, `SoUploadCreate`, `SoUploadDestroy`, `SoUploadDoUpload`, `SoUploadGetErrorCode`, `SoUploadSetOption`, `SoUploadSetPath`, `SoUploadSetTokenServer`, `SoUploadSetTokenUploadApkUrl` …

### `deepscan/deepscan.dll` (x86, 44 导出)
- `ClearTDHQD`, `Create360Object`, `CreateQuarantObject`, `CreateQuarantObjectFactory`, `DSCreateOrUpdateTask`, `DSDeleteTaskByCom`, `DecRefats`, `DllRegisterServer`, `DllUnregisterServer`, `DsEmpEnum`, `DsEmpGetState`, `DsEmpIsSupported`, `DsEmpOpen`, `DsEmpRule`, `DsGetSetSuperKillerSuccFlag`, `DsRKM`, `DsSetScanItemSortList`, `EngLib_Init`, `EngSectionRestore`, `FixDkSec`, `GetDkSecStatus`, `GetModErrCode`, `GetModuleHandle64`, `GetThreadContext64`, `IsAutoRunFilePath`, `IsAutoRunReg`, `IsSupportFeature`, `LdrGetProcedureAddress64`, `ReadProcessMemory64`, `ScanAveMemory`, `ScanAveMemoryWithCode`, `SetDsSrvExePath`, `SetDsSrvName`, `SetHijackEngIncludeMode`, `SetHijackExcludeOrIncludeSt`, `SetLastErrorFromX64Call`, `SetSpkByCk`, `SetThreadContext64`, `VirtualAllocEx64`, `VirtualFreeEx64`, `VirtualProtectEx64`, `VirtualQueryEx64`, `WriteProcessMemory64`, `X64Call`

### `deepscan/CQhCltHttpW.dll` (x86, 36 导出)
- `Init`, `UnInit`, `cancel_cqhcltdns_req`, `cancel_cqhclthttp_req`, `close_cqhcltdns_object`, `close_cqhclthttp_object`, `cqhcltdns_AsyncGetHostByName`, `cqhcltdns_QueryHostByName`, `cqhcltdns_SyncGetHostByName`, `cqhcltdns_SyncGetHostByNameEx`, `cqhclthttp_GetErrorMsg`, `cqhclthttp_GetErrorNo`, `cqhclthttp_GetOpt`, `cqhclthttp_GetToBuffer`, `cqhclthttp_GetToBuffer2`, `cqhclthttp_GetToFile`, `cqhclthttp_GetToFile2`, `cqhclthttp_IsNoContentLen`, `cqhclthttp_PostToBuffer`, `cqhclthttp_PostToBuffer2`, `cqhclthttp_PostToFile`, `cqhclthttp_PostToFile2`, `cqhclthttp_SetOpt`, `cqhclthttp_get_head_info`, `cqhclthttp_setLogParam`, `cqhclthttp_set_head_info`, `cqhclthttp_set_limit_byte`, `cqhclthttp_uploadlog`, `cqhctlhttp_GetCurrentMode`, `cqhctlhttp_GetIP`, `create_cqhcltdns_SetOpt`, `create_cqhcltdns_object`, `create_cqhclthttp_object`, `is_support_afd`, `set_cqhclthttp_mode`, `set_retry_count`

### `deepscan/sysfilerepS.dll` (x86, 24 导出)
- `GetModErrCode`, `WinsxsFix`, `cancel_sysfilerep_req`, `close_sysfilerep_object`, `create_sysfilerep_object`, `fix_ie_kb_fix`, `judgeif_sys_file`, `judgeif_sys_file_a`, `judgeif_sys_file_w`, `replace_all_sys_file`, `replace_all_sys_file_a`, `replace_all_sys_file_w`, `replace_file_w`, `replace_get_http_count`, `replace_set_http_mode`, `replace_set_product_a`, `replace_set_product_w`, `replace_sys_file`, `replace_sys_file_a`, `replace_sys_file_w`, `scan_ie_kb_fix`, `set_download_callback`, `set_option`, `set_sysfilerep_timeout`

### `deepscan/CheckSM.dll` (x86, 14 导出)
- `??0CCheckBad@@QAE@XZ`, `??4CCheckBad@@QAEAAV0@ABV0@@Z`, `CheckBootOsType`, `CheckMbr`, `SetMrbMem`, `SetWineModeInLib`, `fnCheckBad`, `fnCheckBadType`, `fnCopeInMem`, `fnGetMbr`, `fnIsGPT`, `fnIsLinuxOS`, `fnRestoreMBR`, `fnSetWineMode`

### `deepscan/DSFScan.dll` (x86, 14 导出)
- `CreateObject`, `DSFCreate`, `DSFCreateNetEnvObj`, `DSFDestory`, `DSFDestoryNetEnvObj`, `DSFNetEnvCancel`, `DSFNetEnvCheck`, `DSFNetEnvErrCode`, `DSFNetEnvIsExistBlackNDIS`, `DSFNetEnvRmBlackNDIS`, `DSFRedirect`, `DSFStartScan`, `DSFStopScan`, `FixImageAndHostDeep`

### `deepscan/CloudEngine.dll` (x86, 13 导出)
- `Create360SafeEngine`, `CreateCloudEngine`, `CreateCloudEngineLocker`, `CreateFileReportLog`, `CreatePlugin2`, `CreatePlugin3`, `CreatePlugin4`, `CreatePlugin5`, `CreateQuarantine`, `CreateTrustZone`, `ForceMerge360Log`, `GetModErrCode`, `IsSupportFeature`

### `deepscan/Cloudsec3.dll` (x86, 12 导出)
- `Create360Object`, `DSEngLib_Init`, `DecRefats`, `EngCreateObject`, `EngFrontFix`, `GetModErrCode`, `GetStartMds`, `GetStartMdsPlus`, `IsSupportFeature`, `LTDWS_HQD`, `SetDsSrvExePath`, `SetDsSrvName`

### `deepscan/DsArk.dll` (x86, 9 导出)
- `DriverVersion`, `Install`, `OpenDriver`, `SendCommand`, `SendCommand2`, `SendCommandEx`, `SystemBoost`, `Uninstall`, `UninstallUnusedFiles`

### `deepscan/DSMainUI.dll` (x86, 6 导出)
- `CreateRestorePage`, `NotifyBlackDns`, `ProcessBootIniCommandLine`, `ProcessUninstallCommandLine`, `SaveCommandLine`, `UploadFileNotify`

### `deepscan/avescan.dll` (x86, 3 导出)
- `CreateADSAVEScanInstance`, `QueryFileInAVE`, `UpdateAVEng`

### `deepscan/DsSysRepair.dll` (x86, 3 导出)
- `CreateExaminPlugin`, `DsCreateObject`, `DsCreateObject2`

### `deepscan/360QuarantPlugin.dll` (x86, 2 导出)
- `CreateQuarantObject`, `CreateQuarantObjectFactory`

### `deepscan/capi.dll` (x86, 2 导出)
- `CreateEngine`, `srof`

### `deepscan/WiFiSafe.dll` (x86, 2 导出)
- `CreateObject`, `IsFeatureSupport`

### `deepscan/ImAVEng.dll` (x86, 1 导出)
- `Create360Object`

### `deepscan/PopSoftEng.dll` (x86, 1 导出)
- `Create360Object`

## 清理/主页(sweeper/)  （13 模块 / 118 导出）
### `sweeper/TEngine.dll` (x86, 51 导出)
- `CheckResult`, `CheckResultEx`, `Clean`, `CleanCategoryApp`, `CleanCategoryApp2`, `CleanCategoryAppEx`, `CleanEx`, `ClearResult`, `ClearResultEx`, `CreateTraceEngine`, `GetAppById`, `GetAppByIdEx`, `GetAppIconFile`, `GetAppIconHandle`, `GetAppIconHandleEx`, `GetAppRunningProcExe`, `GetAppRunningProcName`, `GetAppScanResult`, `GetAppScanResult2`, `GetAppScanResultEx`, `GetCategoryAppCount`, `GetCategoryAppCountEx`, `GetCategoryAppName`, `GetCategoryAppNameEx`, `GetCategoryInfo`, `GetCategoryInfoEx`, `GetRegistryCategoryID`, `GetScaningItem`, `GetScaningItemEx`, `GetTraceCategory`, `GetTraceCategoryCount`, `GetTraceCategoryCountEx`, `GetTraceCategoryEx`, `InitEngine`, `InitEngineEx`, `IsAppNeedClean`, `IsAppNeedCleanEx`, `LocateItem`, `LocateItemEx`, `Scan`, `Scan2`, `ScanCategoryApp`, `ScanCategoryApp2`, `ScanCategoryAppEx`, `ScanEx`, `SetAppProperty`, `SetScanCallback`, `Stop`, `StopEx`, `TerminateAppRunningProc`, `TerminateRunningProcess`

### `sweeper/SysSweeper.dll` (x86, 14 导出)
- `CreatePluginFactory`, `CreateRecycleBinInterface`, `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `GetItemPaths`, `GetRecycleBinDirectory`, `GetVariantValue`, `IsHaveRubbish`, `RegisterNotifyHWnd`, `SetRecycleBinDirectory`, `SetScanState`, `StopScanRubbish`

### `sweeper/360OKCleanNew.dll` (x86, 10 导出)
- `CreateInterface`, `CreateSiteUIPage`, `DoOKCleanTask`, `GetOKCleanInfo`, `GetShowCleanProShellExt`, `InitPreCreateUI`, `IsSmartAutoCleanOn`, `IsSuppportSysCleanProShellExt`, `RunSysCleanPro`, `SetShowCleanProShellExt`

### `sweeper/360GarbageCleanerShellExt.dll` (x86, 7 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer`, `GetPopupMenu`, `InvokeMenuItem`

### `sweeper/360GarbageCleanerShellExt64.dll` (x64, 7 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer`, `GetPopupMenu`, `InvokeMenuItem`

### `sweeper/CleanUtils.dll` (x86, 7 导出)
- `Check360Sign`, `DecyptRsaData`, `FreeRsaData`, `LoadLibraryqs`, `LoadLibraryqsp`, `ShellExecuteqs`, `ShellExecuteqsp`

### `sweeper/360clean.dll` (x86, 5 导出)
- `CreateSysSweeper`, `GetWndForExamin`, `InitSysSweeper`, `SetTrashCleanInfo`, `UnInitSysSweeper`

### `sweeper/CleanSoft.dll` (x86, 4 导出)
- `CreateCleanSoftScanner`, `CreateInterface`, `CreatePluginFactory`, `CreateSiteUIPage`

### `sweeper/TrashClean.dll` (x86, 4 导出)
- `CreatePlugin`, `CreateTrashCleanInterface`, `IsTrashToastOn`, `SetSweeperNewName`

### `sweeper/CleanSoftEng.dll` (x86, 3 导出)
- `CreateInterface`, `DeleteUnPinItems`, `IsCloudScanAvailable`

### `sweeper/HomeRepair.dll` (x86, 3 导出)
- `CreateObject`, `Create_CloudBase`, `Create_HomeRepairCloudQuery`

### `sweeper/TengineEx.dll` (x86, 2 导出)
- `CreateInterfaceX`, `CreateInterfaceX2`

### `sweeper/statslib.dll` (x86, 1 导出)
- `ProcessStats`

## 网络监控(netmon/)  （29 模块 / 215 导出）
### `netmon/360perfoptm2.dll` (x86, 60 导出)
- `AddAdProcData`, `AddProcData`, `AddServiceData`, `AddSystemOptm`, `CreateBallInfo`, `CreateNetDataSource`, `CreateOptmScanEngine`, `CreateResDataSource`, `CreateUnistallScanEngine`, `DoOptm`, `DoOptm3`, `DoOptmGroupResidual`, `EduModeChanged`, `FastOptm`, `FastOptm2`, `FastOptm3`, `FastOptmForGameMode`, `FastOptmForGameMode3`, `FastOptmSimulate`, `FreeAllData`, `FreeHttpMemory`, `FreePOCallbackData`, `FreePOData`, `FreePointer`, `FreePointerArray`, `FreeProcData`, `FreeProcessInfoData`, `FreeSpeedData`, `GameModeChanged`, `GeDisplayNameByFilePath`, `GetAllData`, `GetGroupInterface`, `GetLevelByScore`, `GetOptmProcess`, `GetOptmService`, `GetOutData`, `GetUnknownData`, `GetWin10Soft`, `InitPerfOptm`, `InitTrayInterface`, `IsLowConfig`, `IsProcessRunningByName`, `KillProcess`, `NMHttpGetBuffer`, `QueryFDGrayInfo`, `QueryGroupInfo`, `RegistGroupResidualNotify`, `RegistInfoWnd`, `RegistSpeedWnd`, `RegistSpeedWnd2`, `SetAutoOptmGroupResidual`, `SetGroupResidualState`, `SetSmartMode`, `TeenModeChanged`, `TerminatePerfOptm`, `UninitPerfOptm`, `UninitPerfOptm2`, `UnregistInfoWnd`, `UnregistSpeedWnd`, `UpdatePopRecord`

### `netmon/360netctrl.dll` (x86, 40 导出)
- `CleanXFDrvAllFlow`, `ConflictDetection`, `ConflictDetectionEx`, `CreateMsgI`, `CreateNetCtrlTpiInterface`, `CreateProtectSpeed`, `CreateUIInterface`, `CreateUIInterface2`, `DllRegisterServer`, `DllUnregisterServer`, `DrvIsRuning`, `FreeMsgI`, `FreeNetCtrlTpiInterface`, `FreeProcFlux`, `FreeProtectProg`, `FreeProtectSpeed`, `FreeUIInterface`, `GetDayFlow`, `GetProcessFlux`, `GetProcessRemoteFlux`, `GetRemoteFlowSwitch`, `GetRunInterface`, `GetRxMaxValue`, `GetTotalFlow`, `GetTotalFlowEx`, `InitProtect`, `InstallXFDrv`, `IsDrvVerSame`, `IsInstallXFDrv`, `ProcessCD`, `QueryInvalidState`, `QuerySupportVer`, `QuerySupportVerEx`, `RepairBFEService`, `SetProgramBlockCnnt`, `SetRemoteFlowSwitch`, `SetXFDrvSwitch`, `UninitProtect`, `UninstCD`, `UninstallXFDrv`

### `netmon/360Netdr.dll` (x86, 11 导出)
- `CheckADSLDial`, `CheckNetCnnt`, `CheckNetworkOK`, `CreateI360DnsdrInterface`, `CreateI360NetdrInterface`, `DllRegisterServer`, `DllUnregisterServer`, `GetIpConfig`, `GetNetEnvInfo`, `RebootNetAdapter`, `SetIpConfig`

### `netmon/360NMConnection.dll` (x86, 11 导出)
- `CMD_DowndLoadAndInstallTip`, `CMD_DownloadNetmSkin`, `CMD_InstallLocalApk`, `CMD_LauchBrowser`, `CMD_SendMessage`, `CMD_SendMsgCopyData`, `CMD_Start360Exe`, `CreateNetmonClient`, `IsConnected`, `RegisterMessageCallback`, `UpdateConnectionConfig`

### `netmon/360SysOpt.dll` (x86, 10 导出)
- `ChangeServiceTypeByName`, `ComplexAction`, `KillProcess`, `KillProcessEx`, `KillProcessInOrder`, `RestartProcess`, `RestartProcessNoArg`, `RestartServiceByName`, `StartServiceByName`, `StopServiceByName`

### `netmon/sysmon.dll` (x86, 10 导出)
- `CreatePluginFactory`, `FreeProcessUsage`, `GetCpuMemoryUsage`, `GetProcessUsage`, `Init`, `SetCalcProcess`, `Start`, `Stop`, `Uninit`, `fnSysmon`

### `netmon/Netgm.dll` (x86, 9 导出)
- `CreateEClassInstance`, `CreateEduInstance`, `CreateInstance`, `CreateInstanceEx`, `CreateNet`, `GetGameTypes`, `PreCQCheck`, `ProcessMonState`, `SetGroupResidualNotifySwitch`

### `netmon/360ps.dll` (x86, 6 导出)
- `CreatePage`, `InitPage`, `IsSupported`, `RunExtFunction`, `RunExtFunction2`, `UnInitPage`

### `netmon/360arpinstdrv.dll` (x86, 5 导出)
- `DllRegisterServer`, `DllUnregisterServer`, `InstallDrv`, `IsInstallDrv`, `UninstallDrv`

### `netmon/360GameIdentify.dll` (x86, 5 导出)
- `CreateIdentifyExt`, `CreateIdentifyExt2`, `CreateIdentifyExt_Local`, `IsGame`, `IsGame2`

### `netmon/360arpui.dll` (x86, 4 导出)
- `CreatePage`, `InitPage`, `IsSupported`, `UnInitPage`

### `netmon/360AskMsg.dll` (x86, 4 导出)
- `CreateKeepAlivePLugin`, `DllRegisterServer`, `DllUnregisterServer`, `SaveMsgContentToFile`

### `netmon/360NetFos.dll` (x86, 4 导出)
- `CreatePage`, `InitPage`, `IsSupported`, `UnInitPage`

### `netmon/360nettj.dll` (x86, 4 导出)
- `CreatePage`, `InitPage`, `IsSupported`, `UnInitPage`

### `netmon/mobileflux.dll` (x86, 4 导出)
- `Create360MobileTrayInt`, `Create360MobileUiInt`, `DllRegisterServer`, `DllUnregisterServer`

### `netmon/netmstart.dll` (x86, 4 导出)
- `DllRegisterServer`, `DllUnregisterServer`, `IsInstall`, `SetupInstall`

### `netmon/sysoptm.dll` (x86, 4 导出)
- `CheckIFVersion`, `CreateInstance`, `CreateInstance2`, `CreateInstance3`

### `netmon/360netmisc.dll` (x86, 3 导出)
- `CreateNetmonClient`, `DllRegisterServer`, `DllUnregisterServer`

### `netmon/360nmdata.dll` (x86, 3 导出)
- `DecryptBuffer`, `EncryptBuffer`, `FreeBuffer`

### `netmon/360ArpPopWnd.dll` (x86, 2 导出)
- `CreateI360ArpPopWnd`, `CreateUpnpDiscover`

### `netmon/360Sensor.dll` (x86, 2 导出)
- `CreateInterface`, `Uninstall`

### `netmon/NetmTray.dll` (x86, 2 导出)
- `Inject`, `UnInject`

### `netmon/NetmTray64.dll` (x64, 2 导出)
- `Inject`, `UnInject`

### `netmon/360nmcloudtipui.dll` (x86, 1 导出)
- `CreateSimpleWindow`

### `netmon/360nmfk.dll` (x86, 1 导出)
- `FKProcess`

### `netmon/360WebIdentify.dll` (x86, 1 导出)
- `GetWebIdentifyState`

### `netmon/360wvmon.dll` (x86, 1 导出)
- `CreateNetmonClient`

### `netmon/NetmLogin.dll` (x86, 1 导出)
- `CreateNetmLogin`

### `netmon/NetmonEP.dll` (x86, 1 导出)
- `CreatePartnerInterface`

## 软件管家(SoftMgr/)  （33 模块 / 281 导出）
### `SoftMgr/SpeedldSetting.dll` (x86, 39 导出)
- `GetAutoSwitchBoottask`, `GetEnableBoottask`, `GetEnableBypassMetro`, `GetEnableDelayNews`, `GetEnableHolidaySkin`, `GetJoinSpeedldTime`, `GetLogBoottime`, `GetShowGame`, `GetShowNews`, `GetShowNewsFirst`, `GetShowSpeedld`, `GetShowWeather`, `GetSpeedldCity`, `GetSpeedldIdleWait`, `GetSpeedldPopConfig`, `GetSpeedldShowTime`, `GetSpeedldSimpleMode`, `IsBoottaskFilesOK`, `IsSpeedldToastOn`, `SetAutoSwitchBoottask`, `SetEnableBoottask`, `SetEnableDelayNews`, `SetEnableHolidaySkin`, `SetJoinSpeedldTime`, `SetLogBoottime`, `SetShowGame`, `SetShowNews`, `SetShowNewsFirst`, `SetShowSpeedld`, `SetShowWeather`, `SetSpeedldCity`, `SetSpeedldIdleWait`, `SetSpeedldPopConfig`, `SetSpeedldShowTime`, `SetSpeedldSimpleMode`, `ShowNewsConfigModalDlg`, `ShowSpeedldCityModalDlg`, `ShowSpeedldConfigModalDlg`, `ShowSpeedldConfigModalDlgUseBrowser`

### `SoftMgr/SpeedupOpt.dll` (x86, 38 导出)
- `CraeteSpeedupHistoryPage`, `CraeteSpeedupOptimizePage`, `CraeteSpeedupRunPage`, `CreateDlgOptimizeConfirm`, `CreateDlgOptimizeConfirm2`, `CreateOptBoottime`, `CreateOptBoottimeEx`, `CreateSiteUIPage`, `CreateSpeedUpTrustListData`, `CreateSpeedupBoottimePage`, `CreateSpeedupOpt`, `CreateStartupOptimizeInfo`, `Destroy_OptimizeHistory`, `GenerateShareImage`, `GetOptimizePageOpenTime`, `GetSpeedUpTrustListItem`, `GetSpeedUpTrustListItemCount`, `InitSpeedupBoottimePage`, `InitSpeedupHistoryPage`, `InitSpeedupOpt`, `InitSpeedupOptimizePage`, `InitSpeedupRunPage`, `IsSpeedldShowBoottimeNow`, `IsSupport_OptimizeHistory`, `IsUwpStartupVersionOk`, `ReleaseSpeedUpTrustListData`, `SUOIsInIgnoreList`, `SUOPutUnIgnore`, `SUOSetIgnore`, `Show_OptimizeHistory`, `UILEMOptimize`, `UIMayRemanent`, `UnInitSpeedupOpt`, `UningoreSpeedUpTrustListItem`, `UninitSpeedupBoottimePage`, `UninitSpeedupHistoryPage`, `UninitSpeedupOptimizePage`, `UninitSpeedupRunPage`

### `SoftMgr/SomAdvUtils.dll` (x86, 37 导出)
- `CreateCleanStartup`, `CreateHipsStartOptimize`, `CreateRealTimeProtectedInterface`, `CreateSuggestDB`, `GetBDToken`, `GetDefaultProgress`, `GetSpeedldBootTime`, `InterfaceDelay`, `InterfaceHelptonMark`, `InterfaceJIT`, `InterfaceLEMOptimize`, `InterfaceNetQuery`, `InterfaceOptimizeMark`, `InterfaceQueryDD`, `InterfaceRemanent`, `InterfaceSimeBonsuming`, `InterfaceSpeedup`, `InterfaceStopScan`, `InterfaceUninstallzip`, `IsCanExtQuery`, `IsCanLemQuery`, `IsCanProcessTask`, `IsCanScanUwp`, `IsDisabledAutorunItem`, `IsExistBDToken`, `IsLemEnv`, `IsPegEnv`, `IsPropertyMatch`, `IsSafemonFilesOk`, `IsSafemonOk`, `IsSeFilesOk`, `NotifyBrowserPageInfo`, `ProcessDisableItemByCloudAction`, `RunSystemTask`, `SetBackgroundExaminationMode`, `TaskMonitor`, `plugins`

### `SoftMgr/GmeApi.dll` (x86, 15 导出)
- `GmeAPI_Init`, `GmeAPI_RegisterCallback`, `GmeAPI_RestartAppIfNecessary`, `GmeAPI_RunCallbacks`, `GmeAPI_Shutdown`, `GmeAPI_UnregisterCallback`, `GmeApps`, `GmeInternal_CreateInterface`, `GmeRemoteStorage`, `GmeUser`, `GmeUserStats`, `GmeUtils`, `gme_invoke_fun`, `gme_register_event`, `gme_unregister_event`

### `SoftMgr/GmeApi64.dll` (x64, 15 导出)
- `GmeAPI_Init`, `GmeAPI_RegisterCallback`, `GmeAPI_RestartAppIfNecessary`, `GmeAPI_RunCallbacks`, `GmeAPI_Shutdown`, `GmeAPI_UnregisterCallback`, `GmeApps`, `GmeInternal_CreateInterface`, `GmeRemoteStorage`, `GmeUser`, `GmeUserStats`, `GmeUtils`, `gme_invoke_fun`, `gme_register_event`, `gme_unregister_event`

### `SoftMgr/360Opt.dll` (x86, 13 导出)
- `CheckSSD`, `CheckSSDEx`, `CreateDiskioEffect`, `CreateLudashiRestore`, `DiskoptInterface`, `GetLatestBoottime`, `GetRealDiskioState`, `QueryOptInterface`, `QuerySpeedOptimizeInterface`, `SetCurrentBoottime`, `SetOptIniKey`, `SetUseNewName`, `UninstallSoftInterface`

### `SoftMgr/NotifyDown.dll` (x86, 13 导出)
- `Get360NotifyDataPath`, `Get360NotifyExeWnd`, `Get360NotifyExeWndByVer`, `Get360NotifyExeWndEx`, `Get360NotifyExeWndExternal`, `Get360UID`, `GetAccountCount`, `GetMailIconsPath`, `Load360NotifyExe`, `Load360NotifyExeEx`, `Load360NotifyExeEx2`, `Load360NotifyExeExternal`, `OnSidebarClick`

### `SoftMgr/CommonBase.dll` (x86, 10 导出)
- `DllGetClassObject`, `GetCheckLockSoft`, `GetCoreComponentList`, `QueryServiceSoftInfo`, `QueryServiceSoftInfo2`, `QueryServiceSoftInfos`, `QueryServiceSoftInfos2`, `ScanSoftListSync`, `StartDownInstSoft`, `querySeCoreState`

### `SoftMgr/Gme.dll` (x86, 9 导出)
- `GmeInit`, `GmeLogin`, `GmeLogout`, `GmePreLogout`, `GmeRTGet`, `GmeRTSet`, `GmeRelease`, `GmeRunGame`, `Gme_Query`

### `SoftMgr/SoftUpdate.dll` (x86, 9 导出)
- `AsyncCreateSoftUpdateCountBmp`, `CreateNewPlugin`, `CreatePluginFactory`, `CreateSoftUpdateCountBmp`, `CreateSoftUpgrade`, `CreateUselessSoftMgr`, `OnUninstall`, `SoftUpgrade_GetSoftCount`, `StopCreateCountBmp`

### `SoftMgr/360SoftMgrS.dll` (x86, 8 导出)
- `CreateInstance`, `DllRegisterServer`, `DllUnregisterServer`, `Initialize`, `ProcessDDService`, `RepairByName`, `RepairDDService`, `Uninitialize`

### `SoftMgr/np360SoftMgr.dll` (x86, 7 导出)
- `DllRegisterServer`, `DllUnregisterServer`, `NP_GetEntryPoints`, `NP_Initialize`, `NP_Shutdown`, `Register`, `UnRegister`

### `SoftMgr/SoftMgrExt.dll` (x86, 7 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer`, `GetOneKeyInstSandBoxInfo`, `Launch`

### `SoftMgr/SoftMgrExt64.dll` (x64, 7 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer`, `GetOneKeyInstSandBoxInfo`, `Launch`

### `SoftMgr/360OptExt.dll` (x86, 6 导出)
- `CreateInstance`, `DllRegisterServer`, `DllUnregisterServer`, `GetForceOptimizer`, `Initialize`, `Uninitialize`

### `SoftMgr/NewKernel.dll` (x86, 6 导出)
- `DllGetClassObject`, `DllGetClassObjectInterface`, `EnumCleanEngWrapper`, `EnumUninstSofts`, `GetCoreComponentList`, `Is35mmConnected`

### `SoftMgr/SMWebProxy.dll` (x86, 5 导出)
- `DllCanUnloadNow`, `DllGetClassObject`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer`

### `SoftMgr/somkernl.dll` (x86, 5 导出)
- `CreateInstance`, `DllGetClassObject`, `SomInitWithFixedMod`, `SomPlugin`, `plugins`

### `SoftMgr/360cfzz.dll` (x86, 4 导出)
- `GetInterface`, `ServiceMain`, `cfzz_001`, `cfzz_002`

### `SoftMgr/ComputerZS1.dll` (x86, 4 导出)
- `IsMutliOS`, `LudashiNeedOpti`, `LudashiOpti`, `LudashiRestore`

### `SoftMgr/360AICenter.exe` (x86, 3 导出)
- `??0ShellResourceRequestDetails@@QAE@XZ`, `??1ShellResourceRequestDetails@@QAE@XZ`, `??4ShellResourceRequestDetails@@QAEAAU0@ABU0@@Z`

### `SoftMgr/GameChrome.exe` (x86, 3 导出)
- `??0ShellResourceRequestDetails@@QAE@XZ`, `??1ShellResourceRequestDetails@@QAE@XZ`, `??4ShellResourceRequestDetails@@QAEAAU0@ABU0@@Z`

### `SoftMgr/SpeedUp.dll` (x86, 3 导出)
- `CreateExtendFastSignObject`, `CreateExtendObjectEx2`, `IsCanExtQuery`

### `SoftMgr/lockkrnl.dll` (x86, 2 导出)
- `CreateDefaultProgramManager`, `CreatePluginFactory`

### `SoftMgr/SoftMgr.exe` (x86, 2 导出)
- `??4OceanDelegate@@QAEAAU0@$$QAU0@@Z`, `??4OceanDelegate@@QAEAAU0@ABU0@@Z`

### `SoftMgr/SoftMgrLiteBase.dll` (x86, 2 导出)
- `SMCCreateInstanceImpl`, `SMCReleaseDLLImpl`

### `SoftMgr/UninstAgent.dll` (x86, 2 导出)
- `DllGetClassObject`, `appLaunch`

### `SoftMgr/zpthdo.dll` (x86, 2 导出)
- `GetInterface`, `RunHelper`

### `SoftMgr/360AdsOpt.dll` (x86, 1 导出)
- `GetAdsOptInterface`

### `SoftMgr/360SoftMgr.cpl` (x86, 1 导出)
- `CPlApplet`

### `SoftMgr/SafeInstallSandbox.dll` (x86, 1 导出)
- `RunSendMessageService`

### `SoftMgr/SafeInstallSandbox64.dll` (x64, 1 导出)
- `RunSendMessageService`

### `SoftMgr/ToastImage.dll` (x86, 1 导出)
- `CreateToastImageInterface`

