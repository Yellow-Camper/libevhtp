SRC      = htparse.c 
OUT      = libhtparse.a
OBJ      = $(SRC:.c=.o)
INCLUDES = -I.
CFLAGS   += -ggdb -Wall -Wextra
LDFLAGS  += 
CC       = gcc

.SUFFIXES: .c

default: $(OUT)

.c.o:
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	ar rcs $(OUT) $(OBJ)

test: $(OUT) test.c
	$(CC) $(INCLUDES) $(CFLAGS) test.c -o test $(OUT)

overflow: $(OUT) overflow.c
	$(CC) $(INCLUDES) $(CFLAGS) overflow.c -o overflow $(OUT)

clean:
	rm -f $(OBJ) $(OUT) test
