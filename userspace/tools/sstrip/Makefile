CC ?= cc
CFLAGS ?= -Wall -Wextra -O2

OBJS = sstrip.o elfrw.o elfrw_ehdr.o elfrw_phdr.o

sstrip: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

$(OBJS): elfrw.h elfrw_int.h

clean:
	rm -f sstrip $(OBJS)

.PHONY: clean
