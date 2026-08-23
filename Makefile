# Nome do executável final
TARGET = firewall

# Compilador que vamos usar
CC = gcc

# Flags de compilação 
CFLAGS = -Wall -Wextra

# Regra padrão do 'make' 
all: $(TARGET)

# Como o 'make' deve construir o seu programa
$(TARGET): firewall.c
	$(CC) $(CFLAGS) firewall.c -o $(TARGET)

# Regra para limpar os arquivos gerados
clean:
	rm -f $(TARGET)