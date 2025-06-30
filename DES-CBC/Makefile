CC=gcc -std=c99 
FLAGS=-Wall -Wshadow
EXEC=DES-CBC
SRC_C=$(EXEC).c

all:
	$(CC) $(FLAGS) -o $(EXEC) $(SRC_C)

encrypt:
	$(CC) $(FLAGS) -o $(EXEC) $(SRC_C)
	./$(EXEC) encrypt input.txt key.txt

decrypt:
	$(CC) $(FLAGS) -o $(EXEC) $(SRC_C)
	./$(EXEC) decrypt encrypted.txt key.txt

clean:
	rm -f *.o *.exe encrypted.txt decrypted.txt