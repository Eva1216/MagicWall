#pragma once
#include "stdafx.h"
WONDERWALL_BOOL_EXPORT	EnumProcess(PROCESSENTRY32* ProcessEntry,ULONG32 Index);
WONDERWALL_NT_EXPORT RhInstallDriver(WCHAR* InDriverPath,WCHAR* InDriverName);

BOOL EnumProcessByCreateToolhelp32Snapshot(PROCESSENTRY32 * ProcessEntry);

BOOL EnumProcessByZwQuerySystemInformation(PROCESSENTRY32 * ProcessEntry);

BOOL EnumProcessBypsapi(PROCESSENTRY32 * ProcessEntry);

BOOL EnumProcessByWTSEnumerateProcesses(PROCESSENTRY32 * ProcessEntry);

BOOL WcharToChar(CHAR ** szDestString, WCHAR * wzSourString);
