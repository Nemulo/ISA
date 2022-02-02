all: popcl

popcl: objects
	g++ main.o socket.o -o popcl -lssl -lcrypto

objects:
	g++ -c socket.cpp -o socket.o
	g++ -c main.cpp -o main.o

clean:
	rm *.o popcl