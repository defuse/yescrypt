#include <stdio.h>
#include <stdint.h>

#define N0 1

static void upgrades(unsigned int step, unsigned int tdiv, unsigned int t0)
{
	uint32_t g;
	uint64_t t, N, sum_t, sum_at;

	printf("Granularity %u, t divisor %u, pre-upgrade t %u\n"
	    "Up #\tt\tN\tsum_t\tsum_AT\tsum_AT %%\n", step, tdiv, t0);

	t = t0; /* NB: t is not in the same units as yescrypt's */
	N = N0;
	sum_t = sum_at = 0;
	for (g = 0; g < 6; g++) {
		sum_t += t * N;
		sum_at += t * N * N;
		if (t * N / N != t || t * N * N / N != t * N ||
		    sum_at < t * N * N)
			break;
		printf("%u\t%llu\t%llu\t%llu\t%llu\t%.2f%%\n",
		    g, (unsigned long long)t, (unsigned long long)N,
		    (unsigned long long)sum_t, (unsigned long long)sum_at,
		    sum_at * 100.0 / ((double)sum_t * sum_t));
		if (step > 1)
			N *= step;
		else
			N = sum_t;
		t = 1 + (t - 1) / tdiv;
	}
}

int main(void)
{
	unsigned int i;

	for (i = 1; i <= 8; i <<= 1)
		upgrades(i, 1, 1);

	putchar('\n');

	for (i = 1; i <= 8; i <<= 1)
		upgrades(4, i, 64);

	putchar('\n');

	for (i = 1; i <= 64; i <<= 1)
		upgrades(4, 2, i);

	return 0;
}
