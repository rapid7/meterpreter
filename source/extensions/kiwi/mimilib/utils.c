/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "utils.h"

void klog(FILE * logfile, PCWCHAR format, ...)
{
	if(logfile)
	{
		va_list args;
		va_start(args, format);
		vfwprintf(logfile, format, args);
		va_end(args);
		fflush(logfile);
	}
}

void klog_password(FILE * logfile, PUNICODE_STRING pPassword)
{
	int i = IS_TEXT_UNICODE_ODD_LENGTH | IS_TEXT_UNICODE_STATISTICS;
	if(pPassword->Buffer)
	{
		if(IsTextUnicode(pPassword->Buffer, pPassword->Length, &i))
			klog(logfile, L"%wZ", pPassword);
		else
			for(i = 0; i < pPassword->Length; i++)
				klog(logfile, L"%02x ", ((LPCBYTE) pPassword->Buffer)[i]);
	}
}