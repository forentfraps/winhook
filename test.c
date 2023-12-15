#include "winhook.h"
#include <stdio.h>

void HookTest(unsigned long long arg1){
    printf("we hooked the function here! original input: %llu\n", arg1);
    printf("Value will be modified to 5678\n");
    decoy(5678);
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