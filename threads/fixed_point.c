#include "threads/fixed_point.h"
#include <stdio.h>
#include <string.h>

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

int sub_mixed(int x, int y)
{
   return x - int_to_fp(y);
}

int mult_fp(int x, int y)
{
   return ((__int64_t) x) * y/F;
}

int mult_mixed(int x, int n)
{
   return x*n;
}

int div_fp(int x, int y)
{
   return ((__int64_t) x)*F / y;
}

int div_mixed(int x, int n)
{
   return x/n;
}