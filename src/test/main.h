#pragma once


#include <ntddk.h> // PsSetCreateProcessNotifyRoutineEx
#include <wdm.h>
#include <minwindef.h>
#include <aux_klib.h>


//////////////////////////////////////////////////////////////////////////////////////////////////


#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define __FILENAMEW__ (wcsrchr(_CRT_WIDE(__FILE__), L'\\') ? wcsrchr(_CRT_WIDE(__FILE__), L'\\') + 1 : _CRT_WIDE(__FILE__))

/*
��֧�ֵ��ַ�Ҳ֧�ֿ��ַ���
ע�⣺
1.�����������ǵ��ַ�������Ϊ�գ�����ҪΪNULL��������ʡ�ԡ�
2.������DPC�ϲ�Ҫ��ӡ���ַ���
3.
*/

//���֧��3����������
#define Print(ComponentId, Level, Format, ...) \
{DbgPrintEx(ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__);}

//�������4��������
#define PrintEx(ComponentId, Level, Format, ...) \
{KdPrintEx((ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__));}


//////////////////////////////////////////////////////////////////////////////////////////////////


#define TAG 'tset' //test


