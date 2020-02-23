SOURCE = dnsflood.c
TARGET = dnsflood
TARBALL = dnsflood.tar.gz

all : $(TARGET)

$(TARGET) : $(SOURCE)
	gcc -o $(TARGET) -O2 -g $(SOURCE)

debug :
	gcc -Wall -o $(TARGET) -g -DDEBUG $(SOURCE)

tarball :
	tar -c -z -f $(TARBALL) $(SOURCE) makefile README.md

clean :
	rm -f $(TARGET)
	rm -f $(TARBALL)
