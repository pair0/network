all: beacon-flood

beacon-flood: main.cpp main.h
	gcc -o beacon-flood main.cpp -lpcap -std=c++0x

clean:
	rm -f beacon-flood *.o
