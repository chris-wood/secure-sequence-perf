all:
	gcc -o perf secure_seq_perf.c md5.c siphash24.c
