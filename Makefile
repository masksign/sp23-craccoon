#	Makefile

XBIN	=	xtest
CC		=	gcc
CFLAGS	+=	-Wall -Wextra -Ofast -march=native
#	(these instrumentation flags will make the code run 10+ times slower)
#CFLAGS	=	-Wall -Wextra -Wshadow -DXDEBUG -fsanitize=address,undefined -O2 -g 
CFLAGS	+=	-Iinc $(RACCF)
CSRC	= 	$(wildcard *.c)
OBJS	= 	$(CSRC:.c=.o)
LDLIBS	=

#	Standard Linux C compile

$(XBIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(XBIN) $(OBJS) $(LDLIBS)

test:	$(XBIN)	
	./$(XBIN)

%.o:	%.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

#	Cleanup

clean:
	cd ref_py && $(MAKE) clean
	$(RM) $(XBIN) $(OBJS)
