#include "header.h"

int main()
{
    //char file[100] = "F:\\Visual Studio\\practice\\myPEloader\\notepad.exe";
    char file[100] = "F:\\qq\\Bin\\QQScLauncher.exe";
    //puts("Enter the name of the file to be processed: ");
    //gets(file);

    PBYTE pBuf = GetAddress(file);

    if (!pBuf)
    {
        printf("Get address Error");

        return -1;
    }

    if (!CheckPE(pBuf))
    {
        printf("PE structure Error");

        return -1;
    }

    if (!LoadPE(pBuf))
    {
        printf("Load PE Error");

        return -1;
    }

    printf("运行起来了(吗？");

    return 0;
}