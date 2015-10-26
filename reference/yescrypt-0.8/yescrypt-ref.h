#ifndef YESCRYPT_REF_H
#define YESCRYPT_REF_H

typedef struct {
	uint32_t *S;
	uint32_t (*S0)[2], (*S1)[2], (*S2)[2];
	size_t w;
} pwxform_ctx_t;

extern void pwxform(uint32_t * B, pwxform_ctx_t * ctx);
extern void salsa20(uint32_t B[16], uint32_t rounds);
extern void pwxform_init(pwxform_ctx_t * ctx, uint32_t * S);

#endif
