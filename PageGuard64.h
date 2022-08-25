#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL WINAPI PG_Initialize(VOID);

BOOL WINAPI PG_CreateHook(LPVOID pTarget, LPVOID pDetour);

BOOL WINAPI PG_EnableHook(LPVOID pTarget);

BOOL WINAPI PG_DisableHook(LPVOID pTarget);

BOOL WINAPI PG_Uninitialize(VOID);

#ifdef __cplusplus
}
#endif