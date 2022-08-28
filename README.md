# PageGuard64

x86/x86_64 MinHook style hooking library utilizing the PAGE_GUARD memory protection to allow for VEH hooking.

## Usage

```c
#include "PageGuard64.h"

int
WINAPI
HkMessageBoxA(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType)
{
    if (!PG_DisableHook(MessageBoxA))
        return 0;

    int result = MessageBoxA(hWnd, "Hooked", lpCaption, uType);

    if (!PG_EnableHook(MessageBoxA))
        return 0;

    return result;
}

int main()
{
    if (!PG_Initialize())
        return 0;

    if (!PG_CreateHook(MessageBoxA, HkMessageBoxA))
        return 0;

    if (!PG_EnableHook(MessageBoxA))
        return 0;

    MessageBoxA(NULL, "Test", "Test", MB_OK);

    if (!PG_DisableHook(MessageBoxA))
        return 0;

    if (!PG_Uninitialize())
        return 0;

    return 1;
}
```
