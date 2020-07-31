#ifndef UTILS_H
#define UTILS_H

#ifndef WITH_SGX
#include <stdio.h>
#include <stdlib.h>
#include <time.h> 
#include "defines.h"

void dump(uint8_t *prefix, uint8_t *buf, unsigned long len);
void print_random_keys(void);
int print_stats(const char *name, double *a, int l);
#endif

void hexlifyn(char *bstr, int bstr_len, char *hstr);
void unhexlifyn(char *hstr, int hstr_len, char *bstr);

#endif