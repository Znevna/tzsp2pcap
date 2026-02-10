# Compiler settings
CC = gcc
CFLAGS = -O2 -s -Wall

# Npcap SDK paths (Adjust this if your SDK is in a different folder)
NPCAP_SDK = ../npcap-sdk
INCLUDES = -I$(NPCAP_SDK)/Include
LIB_PATH = -L$(NPCAP_SDK)/Lib/x64

# Libraries to link
LIBS = -lwpcap -lws2_32

# Target binary name
TARGET = tzsp2pcap.exe
SRC = tzsp2pcap.c

# Build rules
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRC) $(LIB_PATH) $(LIBS)

clean:
	rm -f $(TARGET)
