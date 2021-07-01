CC = gcc
CFLAGS = -Wall

TARGET = arpspoof

all: $(TARGET)
$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c app.c net.c worker.c -pthread -I .
