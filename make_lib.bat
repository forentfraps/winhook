gcc -c winhook.c -o wh.o
gcc -c Zydis.c -o zd.o 
ld -relocatable wh.o zd.o -o winhook.o
del wh.o
del zd.o