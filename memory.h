#pragma once
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

void* my_malloc(size_t size, const char *file, int line, const char *func);
void* my_calloc(size_t count, size_t size, const char *file, int line, const char *func);
void my_free(void *obj, const char *file, int line, const char *func);

