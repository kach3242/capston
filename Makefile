all : pcap_test

pcap_test: main.o pack.o
	g++ -g -o pcap_test main.o pack.o -lpcap

main.o: main.cpp pack.h
	g++ -g -c -o main.o main.cpp

pack.o : pack.cpp pack.h
	g++ -g -c -o pack.o pack.cpp

clean:
	rm -f pcap_test
	rm -f *.o

