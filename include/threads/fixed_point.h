#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

#define F (1 << 14)		/* fixed point */
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

/*** 17.14 fixed point format ***/
/*** Returned number is FP number ***/

int int_to_fp(int n);			/* integer를 FP로 */
int fp_to_int_round(int x);		/* FP를 int로(반올림) */
int fp_to_int(int x);			/* FP를 int로(내림) */
int add_fp(int x, int y);		/* FP끼리 더하기 */
int add_mixed(int x, int n);	/* FP와 정수(int)끼리 더하기 */
int sub_fp(int x, int y);		/* FP끼리 빼기 */
int sub_mixed(int x, int n);	/* FP와 정수(int)끼리 빼기 */
int mult_fp(int x, int y);		/* FP끼리 곱하기 */
int mult_mixed(int x, int n);	/* FP와 정수(int)끼리 곱하기 */
int div_fp(int x, int y);		/* FP끼리 나누기 */
int div_mixed(int x, int n);	/* FP와 정수(int)끼리 나누기 */

/*** Implementations ***/

int int_to_fp(int n)
{
   return n*F;
}

int fp_to_int_round(int x)
{
   return x >= 0 ? (x + F/2)/F : (x - F/2)/F;
}

int fp_to_int(int x)
{
   return x/F;
}

int add_fp(int x, int y)
{
   return x + y;
}

int add_mixed(int x, int n)
{
   return x + int_to_fp(n);
}

int sub_fp(int x, int y)
{
   return x - y;
}

int sub_mixed(int x, int n)
{
   return x - int_to_fp(n);
}

int mult_fp(int x, int y)
{
   return ((int64_t) x) * y/F;
}

int mult_mixed(int x, int n)
{
   return x*n;
}

int div_fp(int x, int y)
{
   return ((int64_t) x)*F / y;
}

int div_mixed(int x, int n)
{
   return x/n;
}


#endif /* threads/fixed_point.h */