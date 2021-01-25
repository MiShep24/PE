#include <windows.h>
#include <Parsers.h>
#include <stdio.h>

void ParseOptionalHeader(IMAGE_OPTIONAL_HEADER header) {
    printf("Start address 0x%p\n", (void*)header.AddressOfEntryPoint);
}