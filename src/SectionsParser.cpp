#include <windows.h>
#include <Parsers.h>
#include <stdio.h>
#include <cstdint>

IMAGE_SECTION_HEADER* ParseSections(IMAGE_NT_HEADERS ntHeaders, FILE* exe, bool print) {
    WORD sectionsAmount = ntHeaders.FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* headers = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * sectionsAmount);

    size_t readSectionsAmount = fread(headers, sizeof(IMAGE_SECTION_HEADER), sectionsAmount, exe);

    if (readSectionsAmount != sectionsAmount) {
        printf("Can't parse sections!\n");
        exit(EXIT_FAILURE);
    }

    if (print) {
        printf("Sections:\n");
        printf("Index               Name                VAddress                VSize               RSize\n");
        for (uint32_t i = 0; i < sectionsAmount; i++) {
            printf("%d              %s                  0x%p                %d              %d\n", i, headers[i].Name, (void*)headers[i].VirtualAddress, headers[i].Misc.VirtualSize, headers[i].SizeOfRawData);
        }

    }
    return headers;
}