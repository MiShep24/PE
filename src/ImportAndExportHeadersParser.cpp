#include <windows.h>
#include <Parsers.h>
#include <stdio.h>
#include <cstdint>

#define ALIGN_DOWN(x, align)  (x & ~(align-1))
#define ALIGN_UP(x, align)    ((x & (align-1))?ALIGN_DOWN(x,align)+align:x)

int DefSection(DWORD rva, WORD numberOfSections, DWORD sectionAlignment, IMAGE_SECTION_HEADER* sections) {
    for (int i = 0; i < numberOfSections; ++i) {
        DWORD start = sections[i].VirtualAddress;
        DWORD end = start + ALIGN_UP(sections[i].Misc.VirtualSize, sectionAlignment);

        if (rva >= start && rva < end)
            return i;
    }
    return -1;
}

DWORD RVAToRaw(DWORD rva, WORD numberOfSections, DWORD sectionAlignment, IMAGE_SECTION_HEADER* sections) {
    int indexSection = DefSection(rva, numberOfSections, sectionAlignment, sections);
    if (indexSection != -1)
        return rva - sections[indexSection].VirtualAddress + sections[indexSection].PointerToRawData;
    else
        return 0;
}

void PrintExportInfo(IMAGE_EXPORT_DIRECTORY dir, WORD numberOfSections, DWORD sectionAlignment, IMAGE_SECTION_HEADER* sections, FILE* exe) {
    printf("Export table:\n");
    DWORD nameAddress = RVAToRaw(dir.Name, numberOfSections, sectionAlignment, sections);
    char name[100];
    if (fseek(exe, nameAddress, SEEK_SET)) {
        fprintf(stderr, "Can't move file pointer!\n");
        exit(EXIT_FAILURE);
    }
    fread(&name, sizeof(char), 100, exe);

    printf("    Name:           %s\n", name);
    printf("    Version:       %d.%d\n", dir.MajorVersion, dir.MinorVersion);
    printf("    Ordinal base:       %lx\n", dir.Base);
    printf("    # of functions:       %d\n", dir.NumberOfFunctions);
    printf("    # of names:       %d\n\n", dir.NumberOfNames);

    DWORD functionAddressesRawAddress = RVAToRaw(dir.AddressOfFunctions, numberOfSections, sectionAlignment, sections);
    DWORD functionNameTableRawAddress = RVAToRaw(dir.AddressOfNames, numberOfSections, sectionAlignment, sections);
    DWORD functionOrdinalsAddress = RVAToRaw(dir.AddressOfNameOrdinals, numberOfSections, sectionAlignment, sections);

    if (fseek(exe, functionAddressesRawAddress, SEEK_SET)) {
        fprintf(stderr, "Can't move file pointer!\n");
        exit(EXIT_FAILURE);
    }
    DWORD* functionAddressesTable = (DWORD*)malloc(sizeof(DWORD) * dir.NumberOfFunctions);
    fread(functionAddressesTable, sizeof(DWORD), dir.NumberOfFunctions, exe);

    if (fseek(exe, functionOrdinalsAddress, SEEK_SET)) {
        fprintf(stderr, "Can't move file pointer!\n");
        exit(EXIT_FAILURE);
    }
    WORD* functionOrdinalsTable = (WORD*)malloc(sizeof(WORD) * dir.NumberOfFunctions);
    fread(functionOrdinalsTable, sizeof(WORD), dir.NumberOfFunctions, exe);

    if (fseek(exe, functionNameTableRawAddress, SEEK_SET)) {
        fprintf(stderr, "Can't move file pointer!\n");
        exit(EXIT_FAILURE);
    }
    DWORD* functionNamesTable = (DWORD*)malloc(sizeof(DWORD) * dir.NumberOfFunctions);
    fread(functionNamesTable, sizeof(DWORD), dir.NumberOfFunctions, exe);

    printf("    Entry pnt   Ordn    Name\n");
    for (DWORD i = 0; i < dir.NumberOfFunctions - 1; i++) {
        DWORD index = functionOrdinalsTable[i] + dir.Base;
        printf("    %lx     %d      ", functionAddressesTable[index], functionOrdinalsTable[index]);

        DWORD functionNameRawAddress = RVAToRaw(functionNamesTable[index], numberOfSections, sectionAlignment, sections);
        if (fseek(exe, functionNameRawAddress, SEEK_SET)) {
            fprintf(stderr, "Can't move file pointer!\n");
            exit(EXIT_FAILURE);
        }

        char buffer[4096] = { 0 };
        size_t bytesRead = fread(&buffer, sizeof(char), sizeof(buffer), exe);

        printf("%s\n", buffer);
    }
}

void PrintImportInfo(IMAGE_IMPORT_DESCRIPTOR descriptor, WORD numberOfSections, DWORD sectionAlignment, IMAGE_SECTION_HEADER* sections, FILE* exe) {
    printf("    Hint/Name Table:    %lx\n", descriptor.OriginalFirstThunk);
    printf("    TimeDateStamp:      %lx\n", descriptor.TimeDateStamp);
    printf("    First thunk RVA:      %lx\n", descriptor.FirstThunk);
    size_t thunksAmount = 40;
    IMAGE_THUNK_DATA* imageThunkDataTable = (IMAGE_THUNK_DATA*)calloc(thunksAmount, sizeof(IMAGE_THUNK_DATA));

    DWORD imageThunkDataTableRawAddress = RVAToRaw(descriptor.OriginalFirstThunk, numberOfSections, sectionAlignment, sections);

    if (fseek(exe, imageThunkDataTableRawAddress, SEEK_SET)) {
        fprintf(stderr, "Can't move file pointer!\n");
        exit(EXIT_FAILURE);
    }

    fread(imageThunkDataTable, sizeof(IMAGE_THUNK_DATA), thunksAmount, exe);

    printf("    Ordinal     Name\n");
    for (uint32_t i = 0; i < thunksAmount; i++) {
        if (imageThunkDataTable[i].u1.AddressOfData < 0) {
            printf("    %lx      %s\n", imageThunkDataTable[i].u1.Ordinal, "Name is unknown");
        }
        DWORD functionStructRawAddress = RVAToRaw(imageThunkDataTable[i].u1.AddressOfData, numberOfSections, sectionAlignment, sections);
        if (functionStructRawAddress == NULL) continue;
        if (fseek(exe, functionStructRawAddress, SEEK_SET)) {
            fprintf(stderr, "Can't move file pointer!\n");
            exit(EXIT_FAILURE);
        }

        IMAGE_IMPORT_BY_NAME functionStruct;
        fread(&functionStruct, sizeof(IMAGE_IMPORT_BY_NAME) - 2, 1, exe);

        char buffer[4096] = { 0 };
        fread(&buffer, sizeof(char), sizeof(buffer), exe);
        printf("    %d          %s\n", functionStruct.Hint, buffer);
    }
}

void ParseImportAndExportHeaders(IMAGE_NT_HEADERS ntHeaders, FILE* exe) {
    WORD sectionsAmount = ntHeaders.FileHeader.NumberOfSections;
    DWORD sectionAlignment = ntHeaders.OptionalHeader.SectionAlignment;

    if (ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL) {

        IMAGE_SECTION_HEADER* sections = ParseSections(ntHeaders, exe, false);

        DWORD exportTableRawAddress = RVAToRaw(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                                               sectionsAmount, sectionAlignment, sections);

        if (fseek(exe, exportTableRawAddress, SEEK_SET)) {
            fprintf(stderr, "Can't move file pointer!\n");
            exit(EXIT_FAILURE);
        }

        IMAGE_EXPORT_DIRECTORY exportDirectory;

        size_t readExportDirs = fread(&exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), 1, exe);

        if (readExportDirs != 1) {
            fprintf(stderr, "Can't read export directory!\n");
            exit(EXIT_FAILURE);
        }

        PrintExportInfo(exportDirectory, sectionsAmount, sectionAlignment, sections, exe);
    }
    else {
        printf("No export table is present!\n");
    }

    if (ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL) {
        IMAGE_SECTION_HEADER* sections = ParseSections(ntHeaders, exe, false);

        DWORD importTableRawAddress = RVAToRaw(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
                                               sectionsAmount, sectionAlignment, sections);

        if (fseek(exe, importTableRawAddress, SEEK_SET)) {
            fprintf(stderr, "Can't move file pointer!\n");
            exit(EXIT_FAILURE);
        }

        IMAGE_IMPORT_DESCRIPTOR* importDescriptorsTable = (IMAGE_IMPORT_DESCRIPTOR*)calloc(40, sizeof(IMAGE_IMPORT_DESCRIPTOR));

        size_t importTableSize = 0;
        importTableSize = fread(importDescriptorsTable, sizeof(IMAGE_IMPORT_DESCRIPTOR), 40, exe);

        if (importDescriptorsTable[0].Name == 0) {
            printf("No standard import table is present!\n");
            return;
        }
        printf("Import table:\n");
        for (size_t i = 0; i < importTableSize; i++) {
            if (importDescriptorsTable[i].Name == 0) break;
            DWORD dllNameRawAddress = RVAToRaw(importDescriptorsTable[i].Name, sectionsAmount, sectionAlignment, sections);
            char buffer[4096] = { 0 };

            if (fseek(exe, dllNameRawAddress, SEEK_SET)) {
                fprintf(stderr, "Can't move file pointer!\n");
                exit(EXIT_FAILURE);
            }
            fread(&buffer, sizeof(char), sizeof(buffer), exe);

            printf("%s\n", buffer);

            PrintImportInfo(importDescriptorsTable[i], sectionsAmount, sectionAlignment, sections, exe);
        }
    }
    else {
        printf("No standard import table present!\n");
    }
}