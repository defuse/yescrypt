#include <stdio.h>
#include <stdint.h>

#define N0 1

static void upgrades(unsigned int step)
{
	uint32_t g;
	uint64_t N, t, at;

	printf("Granularity %u\nUp #\tt\tN\tAT\tAT %%\n", step);

	N = N0;
	t = at = 0;
	for (g = 0; g < 6; g++) {
		t += N;
		at += N * N;
		if (N * N / N != N || at < N * N)
			break;
		printf("%u\t%llu\t%llu\t%llu\t%.2f%%\n",
		    g, (unsigned long long)t, (unsigned long long)N,
		    (unsigned long long)at, at * 100.0 / ((double)t * t));
		if (step > 1)
			N *= step;
		else
			N = t;
	}
}

int main(void)
{
	unsigned int i;

	for (i = 1; i <= 0x100; i <<= 1)
		upgrades(i);

	return 0;
}
