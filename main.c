#define _CRT_SECURE_NO_WARNINGS
#include "util.h"




int main(void) {

	LPSTR get_cmdline = GetCommandLineA();
	char* parse_args = strchr(get_cmdline, ' ') + 1;
	char* next_space = strchr(parse_args, ' ');

	if (!parse_args || !next_space) {
		con_printf("Usage: CouchPotato.exe <ip> <port>\n");
		return 1;
	}

	char ip[16] = { 0 };
	char port[6] = { 0 };
	strncpy(ip, parse_args, next_space - parse_args);
	strcpy(port, next_space + 1);

	EtwPatch(); //todo call indirectly
	// TODO: AmsiPatch()
	// TODO: check_seimpersonate()
	// TODO: oxid_escalate(ip, port)







	return 0;










}