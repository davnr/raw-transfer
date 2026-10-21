CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -lncurses

# Directory dove risiede questo Makefile (es. /path/to/repo/code/)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Root del progetto (un livello sopra alla cartella del Makefile: /path/to/repo)
PROJECT_ROOT := $(abspath $(MAKEFILE_DIR)/..)

# Cartella bin posizionata nella vera root della repo
BIN_DIR := $(PROJECT_ROOT)/bin

SRCS = main.c network_core.c file_browser.c ui_render.c system_utils.c sender_engine.c receiver_engine.c

# Mappa tutti i file oggetto in <root>/bin/
OBJS = $(patsubst %.c, $(BIN_DIR)/%.o, $(SRCS))
EXEC = $(BIN_DIR)/raw-transfer

# Permette a Make di trovare i sorgenti .c nella cartella corrente
VPATH = $(MAKEFILE_DIR)

all: $(BIN_DIR) $(EXEC)

# Crea la cartella bin nella root della repo
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Link dell'eseguibile finale
$(EXEC): $(OBJS)
	$(CC) $(OBJS) -o $(EXEC) $(LDFLAGS)

# Compilazione dei file .o dentro <root>/bin/
$(BIN_DIR)/%.o: %.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Pulizia della cartella bin nella root
clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean
