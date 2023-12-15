#include "winhook.h"
#include <stdio.h>

typedef void (*fpVictim)(unsigned long long);

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

void VictimTest(unsigned long long arg1){
    printf("Dull normal test %llu \n", arg1);
    return;
}

int main(){
    HookInfo h;
    InstallHook(VictimTest, HookTest, &h);
    VictimTest(1234);
    RemoveHook(VictimTest, &h);
    VictimTest(1234);
    printf("Graceful exit\n");
}