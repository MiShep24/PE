#pragma once
#include <winnt.h>
#include <stdio.h>

void ParseFileHeader(IMAGE_FILE_HEADER header);
void ParseOptionalHeader(IMAGE_OPTIONAL_HEADER header);
IMAGE_SECTION_HEADER* ParseSections(IMAGE_NT_HEADERS ntHeaders, FILE *exe, bool print);
void ParseImportAndExportHeaders(IMAGE_NT_HEADERS ntHeaders, FILE* exe);