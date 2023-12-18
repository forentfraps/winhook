gcc -c winhook.c -o wh.o
ld -relocatable wh.o Zydis.o -o winhook.o
del wh.o