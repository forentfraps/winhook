nasm -f win64 utils.asm -o utils.o
gcc test.c winhook.c Zydis.c utils.o -o test.exe
del *.o