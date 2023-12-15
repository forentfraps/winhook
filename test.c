#include "winhook.h"
#include <stdio.h>

typedef void (*fpVictim)(unsigned long long);
typedef void(* fp_printf)(const char *__format);
void HookTest(unsigned long long arg1){
    fpVictim addr = NULL;
    GET_VICTIM_ADDR(&addr);
    printf("we hooked the function here! original input: %llu\n", arg1);
    if (arg1 == 1234){
        printf("Value will be modified to 5678\n");
        addr(5678);
        return;
    }
    addr(arg1);
    return;
}

void HookPrintf(const char *__format, int argument){
    fp_printf pf = NULL;
    GVA(&pf);
    return;
}

void VictimTest(unsigned long long arg1){
    printf("Dull normal test %llu \n", arg1);
    return;
}


int main(){
    HookInfo h;
    // InstallHook(VictimTest, HookTest, &h);
    // VictimTest(1234);
    // RemoveHook(VictimTest, &h);
    // VictimTest(1234);
    InstallHook(printf, HookPrintf, &h);
    printf("my number is 123 == %d\n", 123);
    RemoveHook(printf, &h);
    printf("Graceful exit\n");
}