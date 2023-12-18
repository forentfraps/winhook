# winhook

Decided to write a hooking library for windows, mainly for future projects :D

It utilises external disassembler, since writing my own would take ages. Hook, which it creates is not a simple trampoline and actually lets the function run normally.



## Usage
Add all ".c" and ".h" files to your project.

Include the winhook.h.

Modify the decoy functions in the header to match the arguments of the hooked function and put the decoy at the end of the function.

Example usage is provided in the test.c

## TODO:
 - Check for jump tables, and\or IAT
 - Add an option to hook into remote process
 - Skim down Zydis, since I do not utilise most of it functionality
