#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	unsigned int r, g, s;
	unsigned int r1, i;

	if (argc < 4) {
		printf("Usage: %s r PWXgather PWXsimple\n", argv[0]);
		return 1;
	}

	r = atoi(argv[1]);
	g = atoi(argv[2]);
	s = atoi(argv[3]);

	printf("g * s * 8 = %u\n", g * s * 8);
	printf("rmin = %u\n", (g * s + 127) / 128);

	r1 = 128 * r / (g * s * 8);
	printf("r1 = %u\n", r1);

	if (r1 > 1)
		printf("X = B'_%u\n", r1 - 1);
	else
		printf("X = (0, ..., 0)\n");

	for (i = 0; i < r1; i++)
		printf("B'_%u = X = pwxform(X ^ B'_%u)\n", i, i);

	i = (r1 - 1) * g * s / 8;
	printf("B_%u = H(B_%u)\n", i, i);

	for (i = i + 1; i < 2 * r; i++)
		printf("B_%u = H(B_%u ^ B_%u)\n", i, i, i - 1);

	return 0;
}
