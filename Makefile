CFLAGS = -Wall

.PHONY: clean

network_metrics: main.c
	$(CC) $(CFLAGS) -o network_metrics main.c

clean:
	rm -f network_metrics
