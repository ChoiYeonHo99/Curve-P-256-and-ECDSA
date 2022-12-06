/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었다.
 */
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <gmp.h>
#include "ecdsa.h"
#include "sha2.h"
#include <string.h>

typedef struct {
	size_t hashLen;
	size_t messageLimitLen;
	void (*hashFunction)(const unsigned char *message, unsigned int length,
											 unsigned char *digit);
} hashInfo;

static hashInfo getHashInfo(const int sha2_ndx) {
	switch (sha2_ndx) {
	case SHA224:
		return (hashInfo){SHA224_DIGEST_SIZE, 64, sha224};
		break;
	case SHA256:
		return (hashInfo){SHA256_DIGEST_SIZE, 64, sha256};
		break;
	case SHA384:
		return (hashInfo){SHA384_DIGEST_SIZE, 128, sha384};
		break;
	case SHA512:
		return (hashInfo){SHA512_DIGEST_SIZE, 128, sha512};
		break;
	case SHA512_224:
		return (hashInfo){SHA224_DIGEST_SIZE, 128, sha512_224};
		break;
	case SHA512_256:
		return (hashInfo){SHA256_DIGEST_SIZE, 128, sha512_256};
		break;
	default:
		return (hashInfo){-1, 0, sha224};
		break;
	}
}

const int a = -3;
mpz_t p, n;
ecdsa_p256_t *G;

/** @brief ECC point 상의 덧셈, rpoint = point1 + point2
 *  @note mpz_t p, 정수 a가 정의되어야 합니다. 
 *        p = prime number(modulo)
 *  @param rpoint : 덧셈 결과 ECC point
 *  @param point1 : 대상 ECC point
 *  @param point2 : 대상 ECC point
 *  @example ecc_add(&result, &P, &Q);
 */
static void ecc_add(ecdsa_p256_t *rpoint, const ecdsa_p256_t *const point1, const ecdsa_p256_t *const  point2){
	// point 값들을 mpz 값으로 초기화 한다.
	// lamda, lamda_b, multi2x는 ecc 연산시 필요한 추가 메모리 공간을 위해 사용한다.(임시 변수)
	mpz_t x1, x2, x3, y1, y2, y3, lamda, lamda_b, multi2x;
	mpz_inits(x1, x2, x3, y1, y2, y3, lamda, lamda_b, multi2x, NULL);
	mpz_import(x1, ECDSA_P256/8, 1, sizeof(point1 -> x[0]), 1, 0, point1 -> x); 
	mpz_import(y1, ECDSA_P256/8, 1, sizeof(point1 -> y[0]), 1, 0, point1 -> y); 
	mpz_import(x2, ECDSA_P256/8, 1, sizeof(point2 -> x[0]), 1, 0, point2 -> x); 
	mpz_import(y2, ECDSA_P256/8, 1, sizeof(point2 -> y[0]), 1, 0, point2 -> y); 
	
	mpz_mod(x1, x1, p); mpz_mod(y1, y1, p);
	mpz_mod(x2, x2, p); mpz_mod(y1, y1, p);

	if(mpz_cmp(x1, x2) != 0 || mpz_cmp(y1, y2) != 0){
		// P != Q : ECC Point Addition

		//lamda = (y2-y1) / (x2-x1)
		mpz_sub(lamda, y2, y1); mpz_mod(lamda, lamda, p);
		mpz_sub(lamda_b, x2, x1); mpz_mod(lamda_b, lamda_b, p);

		mpz_invert(lamda_b, lamda_b, p);

		mpz_mul(lamda, lamda, lamda_b); mpz_mod(lamda, lamda, p);


		// x3
		mpz_powm_ui(x3, lamda, 2, p);
		mpz_sub(x3, x3, x1); mpz_mod(x3, x3, p);
		mpz_sub(x3, x3, x2); mpz_mod(x3, x3, p);

		//y3
		mpz_sub(y3, x1, x3); mpz_mod(y3, y3, p);
		mpz_mul(y3, lamda, y3); mpz_mod(y3, y3, p);
		mpz_sub(y3, y3, y1); mpz_mod(y3, y3, p);
	} else{
		// P == Q : ECC Point Doubling

		//lamda = (3*x_1^2 + a) / 2y_1
		mpz_powm_ui(lamda, x1, 2, p);

		mpz_mul_ui(lamda, lamda, 3); mpz_mod(lamda, lamda, p);

		if(a >= 0) 
			mpz_add_ui(lamda, lamda, a);
		else
			mpz_sub_ui(lamda, lamda, -a);

		mpz_mul_ui(lamda_b, y1, 2); mpz_mod(lamda_b, lamda_b, p);
		mpz_invert(lamda_b, lamda_b, p);
		mpz_mul(lamda, lamda, lamda_b); mpz_mod(lamda, lamda, p);

		//x3
		mpz_powm_ui(x3, lamda, 2, p);
		mpz_mul_ui(multi2x, x1, 2); mpz_mod(multi2x, multi2x, p);
		mpz_sub(x3, x3, multi2x); mpz_mod(x3, x3, p);

		//y3
		mpz_sub(y3, x1, x3); mpz_mod(y3, y3, p);
		mpz_mul(y3, lamda, y3); mpz_mod(y3, y3, p);
		mpz_sub(y3, y3, y1); mpz_mod(y3, y3, p);
	}

	mpz_export(rpoint -> x, NULL, 1, ECDSA_P256/8, 1, 0, x3);
	mpz_export(rpoint -> y, NULL, 1, ECDSA_P256/8, 1, 0, y3);
	mpz_clears(x1, x2, x3, y1, y2, y3, lamda, lamda_b, multi2x, NULL);
}

/** @brief ECC point 상의 곱셈, rpoint = point * time
 *  @note mpz_t p, a가 정의되어야 합니다. 
 *        p = prime number(modulo)
 *  @param rpoint : 곱셈 결과 ECC point
 *  @param point : 대상 ECC point
 *  @param time : 덧셈 횟수
 *  @example ecc_mul(&result, P, T);
 */
void ecc_mul(ecdsa_p256_t *rpoint, ecdsa_p256_t point, const mpz_t time){
	ecdsa_p256_t result;
	int resultINF = 1;

	mpz_t t;
	mpz_init(t);
	mpz_set(t, time);

	// Scalar Multiplication
	while(mpz_cmp_si(t, 0) > 0){
		if(mpz_tstbit(t, 0) == 1){
			if(resultINF == 1){ // 무한 원점은 고정된 점이 아니므로 무한 원짐일 시 초기화(= 최초 연산시 값을 복사)
				memcpy(&result, &point, sizeof(ecdsa_p256_t));
				resultINF = 0;
			}
			else
				ecc_add(&result, &result, &point);
		}
		
		mpz_tdiv_q_2exp(t, t, 1);
		ecc_add(&point, &point, &point);
	}
	*rpoint = result;

	mpz_clear(t);
}

/*
 * Initialize 256 bit ECDSA parameters
 * 시스템파라미터 p, n, G의 공간을 할당하고 값을 초기화한다.
 */
void ecdsa_p256_init(void)
{
	unsigned char set_Gx[ECDSA_P256/8] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
	unsigned char set_Gy[ECDSA_P256/8] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};

	mpz_inits(p, n, NULL);
	mpz_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
	mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
	G = (ecdsa_p256_t *)malloc(sizeof(ecdsa_p256_t));

	for (int i = 0; i < (ECDSA_P256/8); i++) {
		G->x[i] = set_Gx[i];
	}

	for (int i = 0; i < (ECDSA_P256/8); i++) {
		G->y[i] = set_Gy[i];
	}
}

/*
 * Clear 256 bit ECDSA parameters
 * 할당된 파라미터 공간을 반납한다.
 */
void ecdsa_p256_clear(void)
{
	mpz_clear(p);
	mpz_clear(n);
	free(G);
}

/*
 * ecdsa_p256_key() - generates Q = dG
 * 사용자의 개인키와 공개키를 무작위로 생성한다.
 */
void ecdsa_p256_key(void *d, ecdsa_p256_t *Q)
{
	gmp_randstate_t rstate;
	mpz_t rand;
	mpz_init(rand);

	//random seed 생성 및 256비트의 랜덤 수 rand(=d)생성
	uint32_t seed = arc4random();
	gmp_randinit_mt(rstate);
	gmp_randseed_ui(rstate, seed);

	mpz_urandomb(rand, rstate, 256);

	// Q = dG
	ecc_mul(Q, *G, rand);
	
	//rand를 d에 export
	mpz_export(d, NULL, 1, ECDSA_P256/8, 1, 0, rand);

	mpz_clear(rand);
}
/*
 * ecdsa_p256_sign(msg, len, d, r, s) - ECDSA Signature Generation
 * 길이가 len 바이트인 메시지 m을 개인키 d로 서명한 결과를 r, s에 저장한다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. r과 s의 길이는 256비트이어야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_sign(const void *msg, size_t len, const void *d, void *_r, void *_s, int sha2_ndx)
{
	// 입력 메시지가 너무 길어 한도를 초과함
	if (len >= 0x1fffffffffffffffLL)
		return ECDSA_MSG_TOO_LONG;
	
	// Hash함수에 따른 e의 길이 hLen과 Hash값을 담을 _e를 선언한다
	size_t hLen;
	unsigned char *_e;
	
	// sha2_ndx에 따른 구조체를 정의한다
	hashInfo hi = getHashInfo(sha2_ndx);

	// 1. e = H(m)
	hLen = hi.hashLen;
	_e = malloc(sizeof(unsigned char) * hLen);
	hi.hashFunction(msg, len, _e);

	// 2. e의 길이가 n의 길이(256비트)보다 길면 뒷 부분은 자른다
	if (hLen > ECDSA_P256 / 8) {
		// n의 길이만큼만 Hash값을 temp_e에 저장한다
		unsigned char temp_e[ECDSA_P256 / 8];
		for (int i = 0; i < ECDSA_P256 / 8; i++) {
			temp_e[i] = _e[i];
		}
		
		// _e를 초기화한 후 n의 길이만큼 다시 생성한다
		free(_e);
		hLen = ECDSA_P256 / 8;
		_e = malloc(sizeof(unsigned char) * hLen);
		
		// 저장한둔 Hash값을 다시 _e에 저장한다
		for (int i = 0; i < ECDSA_P256 / 8; i++) {
			_e[i] = temp_e[i];
		}
	}

	// 사용할 mpz 변수들 선언하는 부분이다
	mpz_t e, k, r, s, x1, invert_k, mpz_d, temp, temp2;
	gmp_randstate_t state;
	mpz_inits(e, k, r, s, x1, invert_k, mpz_d, temp, temp2, NULL);

	// gmp random을 쓰기 위한 사전 준비이다
	gmp_randinit_default(state);
	gmp_randseed_ui(state, arc4random());

	// unsigned char _e를 mpz_t e로 변환한다
	mpz_import(e, hLen, 1, 1, 1, 0, _e);

	do {
		do {
			// 3. 비밀값 k를 무작위로 선택한다 (0 < k < n)
			mpz_set_ui(temp2, 0x01);
			mpz_set(temp, n);
			mpz_sub(temp, n, temp2);
			mpz_urandomm(k, state, temp);
			mpz_add(k, k, temp2);
			// 4. (x1, y1) = kG
			ecdsa_p256_t x1y1;
			ecc_mul(&x1y1, *G, k);
			mpz_import(x1, ECDSA_P256 / 8, 1, 1, 1, 0, x1y1.x);

			// 5. r = x1 mod n
			mpz_mod(r, x1, n);
			
			// 만일 r = 0이면 3번으로 다시 간다
		} while (mpz_cmp_ui(r, 0) == 0);

		// invert_k = k^-1 (mod n)
		mpz_invert(invert_k, k, n);

		// temp = rd mod n;
		mpz_import(mpz_d, ECDSA_P256 / 8, 1, 1, 1, 0, d);
		mpz_mul(temp, r, mpz_d);
		mpz_mod(temp, temp, n);

		// temp = e + rd mod n
		mpz_add(temp, e, temp);
		mpz_mod(temp, temp, n);

		// 6. s = k^-1(e + rd) mod n
		mpz_mul(temp, invert_k, temp);
		mpz_mod(s, temp, n);

		// 만일 s = 0이면 3번으로 다시 간다
	} while (mpz_cmp_ui(s, 0) == 0);

	// 7. (r, s)가 서명 값이다
	mpz_export(_r, NULL, 1, ECDSA_P256 / 8, 1, 0, r);
	mpz_export(_s, NULL, 1, ECDSA_P256 / 8, 1, 0, s);

	// 사용이 끝난 mpz 변수들을 모두 반납한다
	mpz_clears(e, x1, k, r, s, invert_k, mpz_d, temp, temp2, NULL);

	// 모든 과정이 정상적으로 작동했으면 0을 return한다
	return 0;
}
/*
 * ecdsa_p256_verify(msg, len, Q, r, s) - ECDSA signature veryfication
 * It returns 0 if valid, nonzero otherwise.
 * 길이가 len 바이트인 메시지 m에 대한 서명이 (r,s)가 맞는지 공개키 Q로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *_Q, const void *_r, const void *_s, int sha2_ndx)
{
	// 입력 메시지가 너무 길어 한도를 초과함
	if (len >= 0x1fffffffffffffffLL) 
		return ECDSA_MSG_TOO_LONG;
	
	mpz_t tmp, e, r, s;
	mpz_inits(tmp, e, r, s, NULL);
	
	mpz_import(r, ECDSA_P256 / 8, 1, 1, 1, 0, _r);
	mpz_import(s, ECDSA_P256 / 8, 1, 1, 1, 0, _s);

	//step 1
	mpz_set(tmp, n);
	if (mpz_cmp(r, tmp - 1) > 0 || mpz_cmp(s, tmp - 1) > 0){
		mpz_clears(tmp, e, r, s, NULL);
		return ECDSA_SIG_INVALID;
	}
	mpz_clear(tmp);
	
	//step 2
	unsigned char *_e;
	size_t hLen;
	hashInfo hi = getHashInfo(sha2_ndx);
	hLen = hi.hashLen;
	_e = malloc(sizeof(unsigned char) * hLen);
	hi.hashFunction(msg, len, _e);
	
	//step 3
	if (hLen > ECDSA_P256/8) {
	unsigned char temp_e[ECDSA_P256/8];
	for (int i = 0; i < ECDSA_P256 / 8; i++) {
		temp_e[i] = _e[i];
		}
	free(_e);
	hLen = ECDSA_P256/8;
	_e = malloc(sizeof(unsigned char) * hLen);
	for (int i = 0; i < ECDSA_P256/8; i++) {
		_e[i] = temp_e[i];
		}
	}

	//step 4. 𝑢1 = 𝑒*s_invert mod 𝑛, 𝑢2 = 𝑟 *𝑠_invert mod 𝑛
	mpz_t u1, u2, s_invert;
	mpz_inits(u1, u2, s_invert, NULL);
	
	mpz_import(e, hLen, 1, 1, 1, 0, _e);

	mpz_invert(s_invert, s, n); //s^-1
	
	
	mpz_mul(u1, e, s_invert); //u1 = e * s_invert
	mpz_mod(u1, u1, n); //u1 = u1 mod n

	mpz_mul(u2, r, s_invert); //u2 = r * s_invert
	mpz_mod(u2, u2, n); //u2 = u2 mod n

	//step 5 (𝑥1, 𝑦1) = 𝑢1𝐺 + 𝑢2𝑄. 만일 (𝑥1, 𝑦1) = 𝑂이면 잘못된 서명이다.
	mpz_t x1, y1;
	mpz_inits(x1, y1, NULL);
	
	ecdsa_p256_t u1G;
	ecc_mul(&u1G, *G, u1); //u1G

	ecdsa_p256_t u2Q;
	ecc_mul(&u2Q, *_Q, u2); //u2Q
	
	ecdsa_p256_t x1y1;
	ecc_add(&x1y1, &u1G, &u2Q); //xi, yi
	

	mpz_import(x1, ECDSA_P256 / 8, 1, 1, 1, 0, x1y1.x);
	mpz_import(y1, ECDSA_P256 / 8, 1, 1, 1, 0, x1y1.y);
	
	//if ( (x1, y1) == O) return ECDSA_SIG_MISMATCH;
	mpz_t O;
	mpz_init(O);
	mpz_add(O, x1, y1);
	if(mpz_cmp(O, x1) == 0 || mpz_cmp(O, y1) == 0){
		mpz_clears(e, s, u1, u2, s_invert, y1, r, x1, NULL);
		return ECDSA_SIG_INVALID;
	}
	mpz_clears(e, s, u1, u2, s_invert, y1, NULL);

	//step 6
	mpz_t r_tmp; //r_tmp = r mod n
	mpz_init(r_tmp);
	mpz_mod(r_tmp, r, n);
	
	mpz_t x1tmp; //x1tmp = x1 mod n
	mpz_init(x1tmp);
	mpz_mod(x1tmp, x1, n);
	
	if(mpz_cmp(r_tmp, x1tmp) != 0){
		mpz_clears(r, r_tmp, x1, x1tmp, NULL);
		return ECDSA_SIG_MISMATCH;
	}
	
	mpz_clears(r, r_tmp, x1, x1tmp, NULL);

	return 0;
}
