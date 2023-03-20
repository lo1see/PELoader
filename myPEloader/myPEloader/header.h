#pragma once
#include <stdio.h>
#include <windows.h>
#include <stdbool.h>

PBYTE GetAddress(char* file);
bool CheckPE(PBYTE pBuf);
bool LoadPE(PBYTE pBuf);
DWORD Alignment(DWORD Start, DWORD Align);

typedef   BOOL(__cdecl* ProcMain)();


bool LoadPE(PBYTE pBuf)
{
    PIMAGE_DOS_HEADER pDOSheader = (PIMAGE_DOS_HEADER)pBuf;//赋值DOS头
    PIMAGE_NT_HEADERS32 pNTheader = (PIMAGE_NT_HEADERS32)(pBuf + pDOSheader->e_lfanew);//赋值NT头
    PIMAGE_SECTION_HEADER pSecheader = (PIMAGE_SECTION_HEADER)((PBYTE)(pNTheader)+ 0x18 + (pNTheader->FileHeader.SizeOfOptionalHeader));//赋值节区头
    DWORD SecAlign = pNTheader->OptionalHeader.SectionAlignment;//赋值内存偏移
    DWORD FileAlign = pNTheader->OptionalHeader.FileAlignment;//赋值文件偏移

    int VAD;


    //给内存分配空间，并对pAlloc进行初始化
    PBYTE pAlloc = (PBYTE)VirtualAlloc(NULL, pNTheader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (pAlloc == NULL)
    {
        printf("Dump Error");

        return -1;
    }
    memset(pAlloc, 0, pNTheader->OptionalHeader.SizeOfImage);


    //复制头信息
    DWORD dwSizeOfHeader = pNTheader->OptionalHeader.SizeOfHeaders;
    memmove(pAlloc, pBuf, dwSizeOfHeader);


    //开始循环加载Section节区
    if (pNTheader->OptionalHeader.SectionAlignment < pNTheader->OptionalHeader.FileAlignment) {
        printf("File structure Error");

        return -1;
    }
    int num = pNTheader->FileHeader.NumberOfSections;
    while (num)
    {
        DWORD dwVirSize = Alignment(pSecheader->Misc.VirtualSize, SecAlign);
        DWORD dwRealSize = pSecheader->SizeOfRawData > dwVirSize ? dwVirSize : pSecheader->SizeOfRawData;

        memmove(pAlloc + pSecheader->VirtualAddress, pBuf + pSecheader->PointerToRawData, dwRealSize);

        pSecheader = (PIMAGE_SECTION_HEADER)((PBYTE)pSecheader + (BYTE)(sizeof(IMAGE_SECTION_HEADER)));

        num--;
    }//更推荐用VirtualSize来memmove，我这样怪怪的不好


    //RVA TO RAW 这个是没有必要的转换
    /*pSecheader = (PIMAGE_SECTION_HEADER)((PBYTE)(pNTheader)+0x18 + (pNTheader->FileHeader.SizeOfOptionalHeader));
    for (num = 0; num <= pNTheader->FileHeader.NumberOfSections; num++)
    {
        if (pNTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > pSecheader->VirtualAddress) {
            pSecheader = (PIMAGE_SECTION_HEADER)((PBYTE)pSecheader + (BYTE)(sizeof(IMAGE_SECTION_HEADER)));
            continue;
        }

        //pSecheader = (PIMAGE_SECTION_HEADER)((PBYTE)pSecheader - (BYTE)(sizeof(IMAGE_SECTION_HEADER)));
        pBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)(pBaseReloc) - pSecheader->VirtualAddress + pSecheader->PointerToRawData);


        break;
    }
    */


    //开始检测并加载重定位表
    PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(pNTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pAlloc);
    int SizeOfBaseReloc = pNTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    
    if (pNTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != NULL)
    {
        do {
            PWORD TypeOffset = (WORD*)((PBYTE)pBaseReloc + 8);
            num = (pBaseReloc->SizeOfBlock - 8) / 2;
            for (int i = 0; i < num; i++)
            {
                WORD type = TypeOffset[i] >> 12;
                WORD offset = TypeOffset[i] & 0x0FFF;
                int differ = 0;
                if (type == 3)
                {
                    differ = *((DWORD*)(offset + (pBaseReloc->VirtualAddress) + pAlloc)) - pNTheader->OptionalHeader.ImageBase;

                    int p = (DWORD)pAlloc + differ;

                    memmove(pAlloc + offset + pBaseReloc->VirtualAddress, &p, 4);//把理论加载地址改为实际加载地址
                }

            }
            SizeOfBaseReloc -= pBaseReloc->SizeOfBlock;
            pBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseReloc + pBaseReloc->SizeOfBlock);
            
        } while (SizeOfBaseReloc);
    }


    //导入表的处理
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pNTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + pAlloc);

    if (pImport != NULL)
    {
        while (pImport->Name != NULL)
        {
            char DLLname[50];
            strncpy(DLLname, (char *)(pImport->Name + pAlloc), 49);
            HMODULE hProcess = LoadLibrary(DLLname);

            if (!hProcess)
            {
                char err[100];

                sprintf(err, "未找到%s", DLLname);
                MessageBox(NULL, err, "Error", MB_OKCANCEL);

                return false;
            }

            PIMAGE_THUNK_DATA32 pINT = (PIMAGE_THUNK_DATA32)(pImport->OriginalFirstThunk + pAlloc);
            PIMAGE_THUNK_DATA32 pIAT = (PIMAGE_THUNK_DATA32)(pImport->FirstThunk + pAlloc);
            

            while ((DWORD)(pINT->u1.AddressOfData) != NULL)
            {
                PIMAGE_IMPORT_BY_NAME pFucname = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData + pAlloc);
                if (pINT->u1.AddressOfData & IMAGE_ORDINAL_FLAG32)
                {
                    pIAT->u1.AddressOfData = (DWORD)(GetProcAddress(hProcess, (LPCSTR)(pINT->u1.AddressOfData)));
                }
                else
                {
                    pIAT->u1.AddressOfData = (DWORD)(GetProcAddress(hProcess, pFucname->Name));
                }
                pINT++;
                pIAT++;
            }

            pImport++;
        }
    }


    //进入EP执行main函数
    //ProMain pMain = (ProMain)(pNTheader->OptionalHeader.AddressOfEntryPoint + pAlloc);
    //pMain();
    ProcMain MMain = NULL;

    MMain = (ProcMain)(pNTheader->OptionalHeader.AddressOfEntryPoint + pAlloc);

    MMain();

    return true;
}



DWORD Alignment(DWORD Start, DWORD Align)
{
    int t = Start % Align;
    if (t != 0)
    {
        t = (Start / Align) + 1;
    }
    else
    {
        t = Start / Align;
    }


    return t * Align;
}


bool CheckPE(PBYTE pBuf)
{
    PIMAGE_DOS_HEADER pDOSheader = (PIMAGE_DOS_HEADER)pBuf;
    PIMAGE_NT_HEADERS32 pNTheader = (PIMAGE_NT_HEADERS32)(pBuf + pDOSheader->e_lfanew);

    if (pDOSheader->e_magic == IMAGE_DOS_SIGNATURE) {
        if (pNTheader->Signature == IMAGE_NT_SIGNATURE) {
            return true;
        }
    }

    return false;
}


PBYTE GetAddress(char* file)
{
    FILE* fp;
    int last, fsize;
    PBYTE pBuf;

    if ((fp = fopen(file, "rb")) == NULL)
    {
        printf("Open file fail");
        exit(1);
    }

    //计算文件大小
    fseek(fp, 0, SEEK_END);
    last = ftell(fp);
    fsize = last;

    //把文件内容复制到分配的内存区域
    fseek(fp, 0, SEEK_SET);
    pBuf = (PBYTE)malloc(fsize);
    fread(pBuf, fsize, 1, fp);

    return pBuf;
}