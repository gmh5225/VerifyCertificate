#pragma once


#include <ntddk.h> // PsSetCreateProcessNotifyRoutineEx
#include <wdm.h>
#include <minwindef.h>
#include <aux_klib.h>


//////////////////////////////////////////////////////////////////////////////////////////////////


#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define __FILENAMEW__ (wcsrchr(_CRT_WIDE(__FILE__), L'\\') ? wcsrchr(_CRT_WIDE(__FILE__), L'\\') + 1 : _CRT_WIDE(__FILE__))

/*
既支持单字符也支持宽字符。
注意：
1.第三个参数是单字符，可以为空，但不要为NULL，更不能省略。
2.驱动在DPC上不要打印宽字符。
3.
*/

//这个支持3三个参数。
#define Print(ComponentId, Level, Format, ...) \
{DbgPrintEx(ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__);}

//这个最少4个参数。
#define PrintEx(ComponentId, Level, Format, ...) \
{KdPrintEx((ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__));}


//////////////////////////////////////////////////////////////////////////////////////////////////


#define TAG 'tset' //test


