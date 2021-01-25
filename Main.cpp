#include <windows.h>
#include <stdio.h>
#include <winnt.h>

#include <Parsers.h>

#define EMAGIC 0x5A4D
#define PE_SIGNATURE  0x00004550

typedef enum _InfoToParse {
    Headers,
    Sections,
    ImpExp,
} InfoToParse;

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "pedump <option> <executable path>\n");
        fprintf(stderr, "At least one of the following switches must be provided:\n");
        fprintf(stderr, "   -f     Display the contents of file header\n");
        fprintf(stderr, "   -h     Display the contents of sections\n");
        fprintf(stderr, "   -i     Display the contents of import/export tables\n");
        exit(EXIT_FAILURE);
    }

    InfoToParse infoToParse = Headers;

    if (strcmp(argv[1], "-h") == 0) {
        infoToParse = Sections;
    }
    else if (strcmp(argv[1], "-i") == 0) {
        infoToParse = ImpExp;
    }
    else if (strcmp(argv[1], "-f") == 0) {}
    else {
        fprintf(stderr, "Unknown switch!\n");
        exit(EXIT_FAILURE);
    }

    const char* filename = NULL;
    filename = argv[2];

    FILE* exe;

    exe = fopen(filename, "rb");
    if (exe == NULL) {
        printf("Can't open exe file!\n");
        exit(EXIT_FAILURE);
    }

    IMAGE_DOS_HEADER dosHeader;
    size_t readBytes = fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, exe);

    if (!readBytes || dosHeader.e_magic != EMAGIC) {
        printf("Can't read file or incorrect signature!\n");
        exit(EXIT_FAILURE);
    }

    IMAGE_NT_HEADERS ntHeaders;
    if (fseek(exe, dosHeader.e_lfanew, SEEK_SET)) {
        printf("fseek error!\n");
        exit(EXIT_FAILURE);
    }

    size_t readImageHeadersBytes = fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, exe);

    if (!readImageHeadersBytes || ntHeaders.Signature != PE_SIGNATURE) {
        printf("Can't read NT header or incorrect PE signature!\n");
        exit(EXIT_FAILURE);
    }

    printf("%s:\n", filename);

    switch (infoToParse) {
    case Headers:
        ParseFileHeader(ntHeaders.FileHeader);
        ParseOptionalHeader(ntHeaders.OptionalHeader);
        break;
    case Sections:
        ParseSections(ntHeaders, exe, true);
        break;
    case ImpExp:
        ParseImportAndExportHeaders(ntHeaders, exe);
        break;
    }

    fclose(exe);
    return 0;
}
