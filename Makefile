CC = gcc
#-Wall flag and -Wextra flag are compiler warnings for programming mistakes since it will trace the wrong thing if incorrect
CFLAGS = -Wall -Wextra -g

tracer: tracer.c
	$(CC) $(CFLAGS) -o $@ $<

#marked .PHONY since "clean" doesn't actually exist. a real file named clean would otherwise make 'make' skip the rule
.PHONY: clean
clean:
	rm -f tracer