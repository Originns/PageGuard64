#include "PageGuard64.h"

#define INITIAL_HOOK_CAPACITY   32
#define INVALID_HOOK_POS UINT_MAX

typedef struct _PAGE_ENTRY
{
    LPVOID BaseAddress;
    SIZE_T RegionSize;
    DWORD Protection;
} PAGE_ENTRY, * PPAGE_ENTRY;

typedef struct _HOOK_ENTRY
{
    BOOL bActive;
    LPVOID pTarget;
    LPVOID pDetour;
} HOOK_ENTRY, * PHOOK_ENTRY;

HANDLE g_hHeap = NULL;
HANDLE g_hExceptionHandler = NULL;

struct
{
    PHOOK_ENTRY pItems;
    UINT        capacity;
    UINT        size;
} g_hooks;

static UINT FindHookEntry(LPVOID pTarget)
{
    UINT i;
    for (i = 0; i < g_hooks.size; ++i)
    {
        if ((ULONG_PTR)pTarget == (ULONG_PTR)g_hooks.pItems[i].pTarget)
            return i;
    }

    return INVALID_HOOK_POS;
}

static PHOOK_ENTRY AddHookEntry()
{
    if (g_hooks.pItems == NULL)
    {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.pItems = (PHOOK_ENTRY)HeapAlloc(
            g_hHeap, 0, g_hooks.capacity * sizeof(HOOK_ENTRY));
        if (g_hooks.pItems == NULL)
            return NULL;
    }
    else if (g_hooks.size >= g_hooks.capacity)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)HeapReAlloc(
            g_hHeap, 0, g_hooks.pItems, (g_hooks.capacity * 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return NULL;

        g_hooks.capacity *= 2;
        g_hooks.pItems = p;
    }

    return &g_hooks.pItems[g_hooks.size++];
}

static BOOL QueryPage(LPVOID pTarget, PPAGE_ENTRY pEntry)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };

    SIZE_T size = VirtualQuery(pTarget, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

    if (!size)
        return FALSE;

    pEntry->BaseAddress = mbi.BaseAddress;
    pEntry->RegionSize = mbi.RegionSize;
    pEntry->Protection = mbi.Protect;

    return TRUE;
}

static BOOL GetPageProtection(LPVOID pTarget, PDWORD pProtection)
{
    if (!pProtection)
        return FALSE;

    PAGE_ENTRY pEntry = { 0 };

    if (!QueryPage(pTarget, &pEntry))
        return FALSE;

    *pProtection = pEntry.Protection;

    return TRUE;
}

static BOOL ProtectPage(PVOID address, DWORD protection, PDWORD oldProtect)
{
    if (!oldProtect)
    {
        DWORD dwOld;
        return VirtualProtect(address, 1, protection, &dwOld);
    }

    return VirtualProtect(address, 1, protection, oldProtect);
}

static BOOL IsPageGuarded(LPVOID pTarget)
{
    DWORD dwCur;
    if (!GetPageProtection(pTarget, &dwCur))
        return FALSE;

    return dwCur & PAGE_GUARD;
}

static BOOL GuardEntry(PHOOK_ENTRY pEntry)
{
    DWORD dwCur;
    if (!GetPageProtection(pEntry->pTarget, &dwCur))
        return FALSE;

    if (dwCur & PAGE_GUARD)
        return TRUE;

    return ProtectPage(pEntry->pTarget, dwCur | PAGE_GUARD, NULL);
}

static BOOL EnableHookLL(UINT pos, BOOL enable)
{
    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];

    if (pHook->bActive != enable)
    {
        pHook->bActive = enable;
    }

    if (enable)
    {
        GuardEntry(pHook);

        if (!IsPageGuarded(pHook->pTarget))
        {
            // adding the protection didn't work
            return FALSE;
        }
    }

    // dont unguard since there could be other hooks in this page - let the veh handle this

    return TRUE;
}

static VOID RefreshHookLL(UINT pos)
{
    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];

    if (pHook->bActive)
        GuardEntry(pHook);
}

static BOOL EnableHook(LPVOID pTarget, BOOL enable)
{
    UINT pos = FindHookEntry(pTarget);

    if (pos != INVALID_HOOK_POS)
        return EnableHookLL(pos, enable);

    return FALSE;
}

static VOID RefreshHook(LPVOID pTarget)
{
    UINT pos = FindHookEntry(pTarget);

    if (pos != INVALID_HOOK_POS)
        RefreshHookLL(pos);
}

static BOOL EnableALLHooks(BOOL enable)
{
    BOOL status = TRUE;
    UINT i, first = INVALID_HOOK_POS;

    for (i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.pItems[i].bActive != enable)
        {
            first = i;
            break;
        }
    }

    if (first != INVALID_HOOK_POS)
    {

        for (UINT i = 0; i < g_hooks.size; ++i)
        {
            if (g_hooks.pItems[i].bActive != enable)
            {
                status = EnableHookLL(i, enable);
                if (!status)
                    break;
            }
        }
    }

    return status;
}

static VOID RefreshALLHooks()
{
    for (UINT i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.pItems[i].bActive)
        {
            RefreshHookLL(i);
        }
    }
}

static LPVOID HandlePageGuard(LPVOID pAddress)
{
    for (UINT i = 0; i < g_hooks.size; ++i)
    {
        PHOOK_ENTRY pHook = &g_hooks.pItems[i];
        if (pHook->bActive && pHook->pTarget == pAddress)
            return pHook->pDetour;
    }

    return NULL;
}

LONG __stdcall ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        LPVOID pDetour = HandlePageGuard(ExceptionInfo->ExceptionRecord->ExceptionAddress);

        if (pDetour)
        {
            ExceptionInfo->ContextRecord->Rip = (DWORD64)pDetour;
        }

        ExceptionInfo->ContextRecord->EFlags |= 0x100;

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        RefreshALLHooks();

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL WINAPI PG_Initialize(VOID)
{
    if (g_hHeap == NULL)
        g_hHeap = HeapCreate(0, 0, 0);

    if (g_hExceptionHandler == NULL)
        g_hExceptionHandler = AddVectoredExceptionHandler(TRUE, ExceptionHandler);

    return TRUE;
}

BOOL WINAPI PG_CreateHook(LPVOID pTarget, LPVOID pDetour)
{
    if (!pTarget || !pDetour)
        return FALSE;

    UINT pos = FindHookEntry(pTarget);
    if (pos == INVALID_HOOK_POS)
    {
        PHOOK_ENTRY pHook = AddHookEntry();

        pHook->bActive = FALSE;
        pHook->pTarget = pTarget;
        pHook->pDetour = pDetour;
    }
    return TRUE;
}

BOOL WINAPI PG_EnableHook(LPVOID pTarget)
{
    if (pTarget == NULL)
        return EnableALLHooks(TRUE);

    return EnableHook(pTarget, TRUE);
}

BOOL WINAPI PG_DisableHook(LPVOID pTarget)
{
    return EnableHook(pTarget, FALSE);
}

BOOL WINAPI PG_Uninitialize(VOID)
{
    BOOL status = TRUE;

    if (g_hExceptionHandler != NULL)
    {
        status = RemoveVectoredExceptionHandler(g_hExceptionHandler);
    }

    if (g_hHeap != NULL)
    {
        status = EnableALLHooks(FALSE) && status;

        HeapFree(g_hHeap, 0, g_hooks.pItems);
        HeapDestroy(g_hHeap);

        g_hHeap = NULL;

        g_hooks.pItems = NULL;
        g_hooks.capacity = 0;
        g_hooks.size = 0;
    }

    return status;
}