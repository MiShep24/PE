#include <windows.h>
#include <Parsers.h>
#include <stdio.h>

void ParseCharacteristics(WORD characteristics);

void ParseFileHeader(IMAGE_FILE_HEADER header) {
    switch (header.Machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        printf("Architecture: x86-64\n");
        break;
    case IMAGE_FILE_MACHINE_I386:
        printf("Architecture: x86\n");
        break;
    }

    ParseCharacteristics(header.Characteristics);
}

void ParseCharacteristics(WORD characteristics) {
    unsigned char info0;
    unsigned char info1;
    WORD characteristic0 = characteristics & 0x000f;
    WORD characteristic1 = characteristics & 0x00f0;
    printf("Flags:\n");
    switch (characteristic0) {
    case IMAGE_FILE_EXECUTABLE_IMAGE:
        printf("EXECUTABLE_IMAGE, ");
        break;
    }

    switch (characteristic1) {
    case IMAGE_FILE_LARGE_ADDRESS_AWARE:
        printf("LARGE_ADDRESS_AWARE\n");
        break;
    }
}