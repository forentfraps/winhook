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

typedef void (*fp)(unsigned long long arg1);

void HookTest(unsigned long long arg1){
    fp f = NULL;
    GVA(&f);
    printf("we hooked the function here! original input: %llu\n", arg1);
    printf("Value will be modified to 5678\n");
    f(5678);
    return;
}

void VictimTest(unsigned long long arg1){
    printf("Dull normal test %llu \n", arg1);
    return;
}

int main(){
    HookInfo h;
    VictimTest(1234);
    InstallHook(VictimTest, HookTest, &h);
    VictimTest(1234);
    RemoveHook(VictimTest, &h);
    VictimTest(1234);
    printf("Graceful exit\n");
}