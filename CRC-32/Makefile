CC=gcc -std=c99 
FLAGS=-Wall -Wshadow
EXEC=CRC
SRC_C=$(EXEC).c

all:
	$(CC) $(FLAGS) -o $(EXEC) $(SRC_C)
	./$(EXEC) input.txt

clean:
	rm -f $(EXEC).exe CRC-32.txt