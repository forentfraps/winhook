#include "winhook.h"
#include <stdio.h>

typedef void (*fpVictim)(unsigned long long);

typedef NTSTATUS (*fpNtQuerySystemStatus)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength);

NTSTATUS hook(SYSTEM_INFORMATION_CLASS a1,PVOID a2,ULONG a3,PULONG a4){
    fpNtQuerySystemStatus fn = NULL;
    NTSTATUS res;
    GVA(&fn);
    printf("Got a call to NtQuerySystemStatus\n");
    res = fn(a1,a2,a3,a4);
    printf("Result is %lu\n", res);
    return res;
}

int main(){
    HookInfo h;
    fpNtQuerySystemStatus ntqss = NULL;
    // InstallHook(VictimTest, HookTest, &h);
    // VictimTest(1234);
    // RemoveHook(VictimTest, &h);
    // VictimTest(1234);
    ULONG l = 0;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    ntqss = GetProcAddress(ntdll, "NtQuerySystemInformation");
    ntqss(SystemProcessInformation, NULL, 0, &l);
    printf("%lu\n", l);
    InstallHook(ntqss, hook, &h);
    ntqss(SystemProcessInformation, NULL, 0, &l);
    printf("%lu\n", l);
    ntqss(SystemProcessInformation, NULL, 0, &l);
    printf("%lu\n", l);
    ntqss(SystemProcessInformation, NULL, 0, &l);
    printf("%lu\n", l);
    RemoveHook(ntqss, &h);
    printf("Graceful exit\n");
}