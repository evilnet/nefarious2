/*
 * ircd_string_t.c - string test program
 */
#include "ircd_string.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_strtoint(void)
{
  int v = 5;

  assert(ircd_strtoint("0", &v) == 1 && v == 0);
  assert(ircd_strtoint("60000", &v) == 1 && v == 60000);
  assert(ircd_strtoint("-1", &v) == 1 && v == -1);
  assert(ircd_strtoint("0x10", &v) == 1 && v == 16);
  assert(ircd_strtoint(" 42 ", &v) == 1 && v == 42);
  assert(ircd_strtoint("2147483647", &v) == 1 && v == 2147483647);
  assert(ircd_strtoint("-2147483648", &v) == 1 && v == -2147483647 - 1);

  v = 5;
  /* strtoul() into an int made these 0, 1 and -2147483648 */
  assert(ircd_strtoint("4294967296", &v) == 0);
  assert(ircd_strtoint("-4294967295", &v) == 0);
  assert(ircd_strtoint("2147483648", &v) == 0);
  assert(ircd_strtoint("-2147483649", &v) == 0);
  assert(ircd_strtoint("99999999999999999999999", &v) == 0);
  assert(ircd_strtoint("", &v) == 0);
  assert(ircd_strtoint("   ", &v) == 0);
  assert(ircd_strtoint("abc", &v) == 0);
  assert(ircd_strtoint("12abc", &v) == 0);
  assert(ircd_strtoint("1 2", &v) == 0);
  assert(ircd_strtoint("TRUE", &v) == 0);
  assert(ircd_strtoint(NULL, &v) == 0);
  assert(v == 5);
  printf("ircd_strtoint: ok\n");
}

int main(void)
{
  char* vector[20];
  char* names;
  int count;
  int i;

  test_strtoint();

  names = strdup(",,,a,b,a,X,ne,blah,A,z,#foo,&Bar,foo,,crud,Foo,z,x,bzet,,");
  printf("input: %s\n", names);
  count = unique_name_vector(names, ',', vector, 20);
  printf("count: %d\n", count);
  printf("output:");
  for (i = 0; i < count; ++i)
    printf(" %s", vector[i]);
  printf("\n");
  free(names);

  names = strdup("foo");
  printf("input: %s\n", names);
  count = unique_name_vector(names, ',', vector, 20);
  printf("count: %d\n", count);
  printf("output:");
  for (i = 0; i < count; ++i)
    printf(" %s", vector[i]);
  printf("\n");
  free(names);
  
  names = strdup("");
  printf("input: %s\n", names);
  count = unique_name_vector(names, ',', vector, 20);
  printf("count: %d\n", count);
  printf("output:");
  for (i = 0; i < count; ++i)
    printf(" %s", vector[i]);
  printf("\n");
  free(names);

  names = strdup("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z");
  printf("input: %s\n", names);
  count = unique_name_vector(names, ',', vector, 20);
  printf("count: %d\n", count);
  printf("output:");
  for (i = 0; i < count; ++i)
    printf(" %s", vector[i]);
  printf("\n");
  free(names);

  return 0;
}
  
