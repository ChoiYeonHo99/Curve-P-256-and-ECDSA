# Curve-P-256-and-ECDSA
## 문제
표준문서 NIST FIPS 186-4에 명시된 ECDSA (Elliptic Curve Digital Signature Algorithm) 전자서명  
기법을 타원곡선 P-256 상에서 구현한다.
## Curve P-256
타원곡선 P-256은 다음과 같이 정의한다.  
𝑦^2 = 𝑥^3 − 3𝑥 + 𝑏 (mod 𝑝)  
여기서 𝑝는 길이가 256비트인 소수로 다음 값을 사용한다. 모든 수는 16진수로 표현하였다.  

𝑝 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF  

위 조건을 만족하는 타원곡선의 점들은 유한체를 이루는데, 이 과제에서 사용할 그룹의 기저점(base  
point)과 차수(order)는 다음과 같다.  

𝑛 = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  
𝐺𝑥 = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296  
𝐺𝑦 = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5  

소수 𝑛은 그룹의 차수이고, 𝐺가 기저점이므로 𝑛𝐺 = 𝑂를 만족한다. 여기서 𝑂는 무한대 점으로 항등원이다.
## ECDSA
서명자의 개인키가 𝑑이고, 공개키가 𝑄 = 𝑑𝐺일 때, 메시지 𝑚에 대한 ECDSA 전자서명 알고리즘은  
다음과 같다.  

• 서명 (Signature Generation)  
1. 𝑒 = 𝐻(𝑚). 𝐻()는 SHA-2 해시함수이다.  
2. 𝑒의 길이가 𝑛의 길이(256비트)보다 길면 뒷 부분은 자른다. 𝑏𝑖𝑡𝑙𝑒𝑛(𝑒) ≤ 𝑏𝑖𝑡𝑙𝑒𝑛(𝑛)  
3. 비밀값 𝑘를 무작위로 선택한다. (0 < 𝑘 < 𝑛)  
4. (𝑥1, 𝑦1) = 𝑘𝐺.  
5. 𝑟 = 𝑥1 mod 𝑛. 만일𝑟 = 0이면 3번으로 다시 간다.  
6. 𝑠 = 𝑘^−1(𝑒 + 𝑟𝑑) mod 𝑛. 만일 𝑠 = 0이면 3번으로 다시 간다.  
7. (𝑟, 𝑠)가 서명 값이다.  

• 검증 (Signature Verification)  
1. 𝑟과 𝑠가 [1, 𝑛 − 1] 사이에 있지 않으면 잘못된 서명이다.  
2. 𝑒 = 𝐻(𝑚). 𝐻()는 서명에서 사용한 해시함수와 같다.  
3. 𝑒의 길이가 𝑛의 길이(256비트)보다 길면 뒷 부분은 자른다. 𝑏𝑖𝑡𝑙𝑒𝑛(𝑒) ≤ 𝑏𝑖𝑡𝑙𝑒𝑛(𝑛)  
4. 𝑢1 = 𝑒 * 𝑠^−1 mod 𝑛, 𝑢2 = 𝑟 * 𝑠^−1 mod 𝑛.  
5. (𝑥1, 𝑦1) = 𝑢1𝐺 + 𝑢2𝑄. 만일 (𝑥1, 𝑦1) = 𝑂이면 잘못된 서명이다.  
6. 𝑟 ≡ 𝑥1 (mod 𝑛)이면 올바른 서명이다.  
## GMP 함수
GNU GMP 라이브러리에는 크기가 264보다 큰 수를 계산하기 위한 여러 가지 함수가 있다. 이 과제는  
길이가 256비트인 큰 수를 사용하여 계산한다. 과제를 수행하기 위해서는 이들 함수에 대한 지식이 필요  
하다. 함수의 수가 많기 때문에 다 이해하는 것은 시간이 많이 소요된다. 다행스럽게 ECDSA 계산에 꼭  
필요한 함수의 수는 그렇게 많지 않다. 메뉴얼을 참조해서 다음에 열거한 함수의 사용법을 잘 숙지한다.  

• 초기화/삭제: mpz_init(), mpz_inits(), mpz_clear(), mpz_clears()  
• 값 설정: mpz_set(), mpz_set_ui(), mpz_set_str(), mpz_get_str()  
• 산술연산1: mpz_add(), mpz_add_ui(), mpz_sub(), mpz_sub_ui(), mpz_mul(),  
• 산술연산2: mpz_mul_ui(), mpz_mod(), mpz_mod_ui(), mpz_powm(), mpz_powm_ui()  
• 비교연산: mpz_cmp(), mpz_cmp_ui()  
• 비트연산1: mpz_and(), mpz_ior(), mpz_xor(), mpz_com()  
• 비트연산2: mpz_setbit(), mpz_clrbit(), mpz_combit(), mpz_tstbit()  
• 정수론: mpz_probab_prime_p(), mpz_gcd(), mpz_lcm(), mpz_invert()  
• 입출력: mpz_out_str(), mpz_inp_str()  
• 난수: mpz_urandomb(), mpz_urandomm(), gmp_randinit_default()  
• 데이터 변환: mpz_import(), mpz_export()
## 함수 구현
ECDSA 전자서명 기법을 타원곡선 P-256 상에서 구현하는데 필요한 함수의 프로토타입을 아래에 열거  
하였다. 각 함수에 대한 요구사항은 다음과 같다.  

• void ecdsa_p256_init(void) – 시스템 파라미터 𝑝, 𝑛, 𝐺의 공간을 할당하고 값을 초기화한다.  

• void ecdsa_p256_clear(void) – 할당된 파라미터 공간을 반납한다.  

• void ecdsa_p256_key(void *d, ecdsa_p256_t *Q) –사용자의 개인키와 공개키를 무작위로 생성한다.  

• int ecdsa_p256_sign(const void *m, size_t len, const void *d, void *r,  
void *s, int sha2_ndx) –길이가len바이트인메시지m을개인키d로서명한결과를r, s에  
저장한다. sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,  
SHA512_224, SHA512_256 중에서 선택한다. r과 s의 길이는 256비트이어야 한다. 성공하면 0,  
그렇지 않으면 오류 코드를 넘겨준다.  

• int ecdsa_p256_verify(const void *m, size_t len, const ecdsa_p256_t *Q,  
const void *r, const void *s, int sha2_ndx) – 길이가 len 바이트인 메시지 m에 대한  
서명이 (r,s)가 맞는지 공개키 Q로 검증한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
## 오류 코드
ECDSA 실행 과정에서 발생하는 오류를 아래에 열거한 코드를 사용하여 식별한다.  
• ECDSA_MSG_TOO_LONG – 입력 메시지가 너무 길어 한도를 초과함  
• ECDSA_SIG_INVALID – 검증 과정에서 형식이나 값이 잘못된 서명  
• ECDSA_SIG_MISMATCH – 검증 마지막 단계에서 값이 일치하지 않는 서명 불일치
## ECDSA 테스트 벡터
다음은 타원곡선 P-256 상에서 SHA-384 해시함수를 사용해서 생성한 검증 벡터이다. 아래 벡터를 사용  
하여 프로그램이 올바르게 돌아가는지 확인한다.  

Curve P-256:  
y^2 = x^3 - 3x + b (mod p)  

Group prime:  
p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF 

Group order:  
n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  

Group base point:  
Gx = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296  
Gy = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5  

Private key:  
d = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721  

Signature with SHA-384, message = "sample":  

k = 09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4  
x1 = 0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719  
y1 = BB78F0E6EC1BC1F3DC0900D3C4F2955D1E27865BEE7AC17E57D465E06F981D86  
e = 9A9083505BC92276AEC4BE312696EF7BF3BF603F4BBD381196A029F340585312  
r = 0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719  
s = 4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954  
## 골격 파일
구현이 필요한 골격파일 ecdsa.skeleton.c와 함께 헤더파일 ecdsa.h, 프로그램을 검증할 수 있는  
test.c, SHA-2 오픈소스 sha2.c, sha2.h 그리고 Makefile을 제공한다. 이 가운데 test.c, sha2.c,  
sha2.h를 제외한 나머지 파일은 용도에 맞게 자유롭게 수정할 수 있다.
