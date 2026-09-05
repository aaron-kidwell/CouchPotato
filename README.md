# CouchPotato

Make sure you compile on your own to avoid detection.. certain strings are XOR at compile time

Usage: CouchPotato.exe ip port

Patches ETW & AMSI and uses indirect syscall to abuse SeImpersonatePrivilege.

Service account || Admin -> NT system
