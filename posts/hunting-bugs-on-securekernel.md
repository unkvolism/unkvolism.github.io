This post is about what I found doing static analysis on `securekernel.exe` in IDA Pro. Specifically, the cross-VTL data transfer interface and a handler chain that didn't sit right with me after I traced it.

## Quick background on the architecture

If you already know VTL 0 / VTL 1 and how Secure Calls work, skip this. If not: when VBS is active, Windows runs in two isolated contexts enforced by the hypervisor. VTL 0 is the normal world kernel, drivers, everything. VTL 1 is the Secure Kernel. Hyper-V configures the EPT so VTL 1 can read VTL 0 memory but not the other way around. The Secure Kernel stores cryptographic material for IUM processes, enforces HVCI code integrity, protects Credential Guard secrets. The only way VTL 0 talks to VTL 1 is through a defined interface: Secure Calls, which eventually become a `VMCALL` instruction intercepted by Hyper-V.

The entry function on the VTL 1 side is `IumInvokeSecureService`. This is where I started.

## IumInvokeSecureService

The function takes a pointer to `SECURE_CALL_ARGS` as its first parameter. Field `a1+2` is the service code a 16-bit value that selects which handler runs. The body is a switch statement. There's no dispatch table, just a direct switch over the service code. Any unknown value hits the default case:

```c
default:
    SkeBugCheckEx(0x121u, 0xFFFFFFFFC000001CuLL, v18, 0LL, 0LL);
```

`0x121` is `DRIVER_VIOLATION`. No graceful rejection the system dies. I thought that was a deliberate design choice to make fuzzing harder: you can't probe invalid codes without crashing the guest.

The `SECURE_CALL_ARGS` layout is straightforward. `a1+8` onwards are 8-byte slots, all caller-controlled from VTL 0. When the dispatcher routes to a case, it reads those slots directly:

```c
v18 = *((unsigned __int16 *)a1 + 1);  // service code

switch ( (int)v18 )
{
    // ...

    case 8:   // CREATE_THREAD
        Thread = SkpsCreateThread(
                     *((_QWORD *)a1 + 1),
                     *((_QWORD *)a1 + 2),
                     *((_QWORD *)a1 + 3),
                     *((_QWORD *)a1 + 4),
                     *((_QWORD *)a1 + 5),
                     *((_QWORD *)a1 + 6),
                     *((_QWORD *)a1 + 7),
                     (__int64)(a1 + 16));
        goto LABEL_1224;

    case 25:  // CREATE_SECURE_IMAGE
        Thread = SkmmCreateSecureImageSection(
                     *((_QWORD *)a1 + 1),
                     *((_QWORD *)a1 + 2),
                     (unsigned __int8)a1[24],
                     *((_DWORD *)a1 + 8),
                     *((_DWORD *)a1 + 10),
                     (__int64)(a1 + 16));
        goto LABEL_1224;

    case 28:  // PREPARE_IMAGE_RELOCATIONS
        // ...

    default:
        SkeBugCheckEx(0x121u, 0xFFFFFFFFC000001CuLL, v18, 0LL, 0LL);
}
```

I started mapping which services called `SkmmMapDataTransfer` the function responsible for creating a safe mapping of VTL 0 memory inside VTL 1. I ran a quick IDC script to enumerate callers:

```c
#include <idc.idc>

static main()
{
    auto target, xref, caller;

    target = LocByName("SkmmMapDataTransfer");
    if (target == BADADDR)
    {
        Message("not found\n");
        return;
    }

    Message("SkmmMapDataTransfer @ %x\n\n", target);

    xref = CodeRefsTo(target, 0);
    while (xref != BADADDR)
    {
        caller = GetFunctionName(xref);
        Message("  %x  %s\n", xref, caller);
        xref = CodeRefsTo(target, 1);
    }
}
```

38 callers. Most were fine they call `SkmmMapDataTransfer`, do something with the mapped data, and clean up. The case 25 / case 28 chain was different.

```
SkmmMapDataTransfer @ 140037ef8

  140014445 - IumInvokeSecureService
  140014c84 - IumInvokeSecureService
  140014f0e - IumInvokeSecureService
  1400154e4 - IumInvokeSecureService
  140015b61 - IumInvokeSecureService
  14001655b - IumInvokeSecureService
  140016613 - IumInvokeSecureService
  140016a9b - IumInvokeSecureService
  140016b72 - IumInvokeSecureService
  1400176d5 - IumInvokeSecureService
  140017dca - IumInvokeSecureService
  1400180f5 - IumInvokeSecureService
  140018274 - IumInvokeSecureService
  1400187da - IumInvokeSecureService
  140018c26 - IumInvokeSecureService
  1400193ba - IumInvokeSecureService
  140019ce1 - IumInvokeSecureService
  14001a144 - IumInvokeSecureService
  14002777f - IumpCaptureTransfer
  140027812 - IumpCaptureTransferMdl
  14002f2a0 - SkmmObtainHotPatchUndoTable
  14002f640 - SkmmQueryActiveSecurePatch
  140049742 - SkmmDebugReadWriteMemory
  14004c9f3 - SkmmCreateExposedSecureSection
  14004ee23 - SkmiCaptureAndValidateImageData
  14004ef81 - SkmiCaptureAndValidateImageIat
  140052336 - SkmiValidateDynamicCodePages
  140052a07 - SkmmCreateSecureImageSection
  140054613 - SkmmValidateSecureImagePages
  14005941f - SkmmCreateEnclave
  140059c27 - SkmmLoadEnclaveData
  14005a00d - SkmmLoadEnclaveModule
  140070d0d - SkmiReapplyImportRelocationsOnImage
  14007c8b3 - SkhalEfiInvokeRuntimeService
  140086a8d - SkeStartProcessor
  1400abec3 - SkAllocateNormalModePool
  1400ac660 - SkProduceRuntimeSignedReport
  1400b6b40 - SkTransformDumpKey
```

## Case 25: CREATE_SECURE_IMAGE

Case 25 calls `SkmmCreateSecureImageSection`. It takes a PE image from VTL 0, maps it in, reads fields from the PE header `SizeOfImage`, `SizeOfHeaders` and a few others and stores them in a Secure Kernel image object. Those values land at specific offsets in the object: `v7[38]` gets `SizeOfImage`, `v7[39]` gets `SizeOfHeaders`. The handler returns a handle to the image object back to VTL 0.

No validation on the size passed to `SkmmMapDataTransfer` at this point. Whatever VTL 0 sends goes through.

## Case 28: PREPARE_IMAGE_RELOCATIONS

Case 28 takes the handle from case 25 and prepares the image for relocation. Here's the full handler from the dispatcher:

```c
case 28:
    v409 = *((_QWORD *)a1 + 1);
    v410 = *((_QWORD *)a1 + 4);
    v411 = *((_QWORD *)a1 + 3);
    LOBYTE(a3) = 1;
    v620 = 0LL;
    inited = SkobReferenceObjectByHandle(v409, 0, a3, (unsigned int)&SkmiImageType, (__int64)&v620, 0LL);
    if ( inited < 0 )
        goto LABEL_377;
    v412 = v620;
    if ( (*v620 & 0x20) == 0 )
    {
        SKMI_IMAGE_SECURITY(11, 0, (_DWORD)v620, 0, 0LL);
        inited = -1073741819;
        SkobDereferenceObject(v412);
        goto LABEL_1225;
    }
    if ( (v620[37] & 4) == 0 )
    {
        inited = -1073740760;
        SkobDereferenceObject(v620);
        goto LABEL_1225;
    }
    if ( !v620[38] )
    {
        inited = 0;
        SkobDereferenceObject(v620);
        goto LABEL_1225;
    }
    inited = SkmiLockImageExclusive(v620);
    if ( inited < 0 )
        goto LABEL_876;
    if ( *((_QWORD *)v412 + 20) )
    {
        v412[32] = 0;
        inited = 255;
        SkobDereferenceObject(v412);
    }
    else
    {
        v413 = (unsigned int)v412[39];
        v414 = v412[38];
        v612 = 0LL;
        v622 = 0LL;
        v621 = 0LL;
        inited = SkmiCaptureAndValidateImageData(
                     (_DWORD)v412,
                     v411,
                     v410,
                     v414,
                     0,           // a5 hardcoded to zero
                     v413,
                     (__int64)&v612,
                     (__int64)&v622,
                     (__int64)&v621);
        if ( inited >= 0 )
        {
            v415 = (unsigned __int64)v612;
            if ( v621 == *((_DWORD *)v612 + 1) )
            {
                v416 = (void *)SkAllocatePool(512LL, v621, 1346923849LL);
                v417 = v416;
                if ( v416 )
                {
                    memmove(v416, (const void *)v415, *(unsigned int *)(v415 + 4));
                    *((_QWORD *)v412 + 20) = v417;
                }
                else
                {
                    inited = -1073741670;
                }
            }
            else
            {
                inited = -1073741701;
            }
            SkmmFreeIndependentPages(v415 & 0xFFFFFFFFFFFFF000uLL, v622);
            v412[32] = 0;
LABEL_876:
            SkobDereferenceObject(v412);
        }
        else
        {
            v612 = 0LL;
            v412[32] = 0;
            SkobDereferenceObject(v412);
        }
    }
    goto LABEL_1225;
```

Three guard checks before reaching the interesting code. Bit `0x20` in the image object flags, bit `0x4` in `v620[37]`, and `v620[38]` being non-zero. That last one is `SizeOfImage` the value that came from the PE header in case 25 and that VTL 0 controls.

The call to `SkmiCaptureAndValidateImageData` passes `a5 = 0` hardcoded. That matters. Here's the function:

```c
__int64 __fastcall SkmiCaptureAndValidateImageData(
        __int64 a1,
        __int64 a2,
        ULONG_PTR a3,
        unsigned __int64 a4,
        int a5,
        __int64 a6,
        __int64 a7,
        size_t *a8,
        _QWORD *a9)
{
    _QWORD *v9;
    __int64 v10;
    size_t *v11;
    int v14;
    int v15;
    size_t v16;
    char *IndependentPages;
    char *v18;
    _QWORD *v19;

    v9  = (_QWORD *)a7;
    v10 = 0LL;
    v11 = a8;
    a7  = 0LL;
    *v9  = 0LL;
    *v11 = 0LL;

    v14 = SkmmMapDataTransfer(a2, a3, 1u, &a7, 0LL);
    if ( v14 >= 0 )
    {
        v10 = a7;
        v15 = *(_DWORD *)(a7 + 44);
        if ( v15 == (a4 & 0xFFF) && (!a5 || *(_DWORD *)(a7 + 40) == a5) )
        {
            v16 = ((v15 & 0xFFF) + *(unsigned int *)(a7 + 40) + 4095LL)
                    & 0xFFFFFFFFFFFFF000ULL;

            IndependentPages = (char *)SkmmAllocateIndependentPages(v16);
            v18 = IndependentPages;

            if ( IndependentPages )
            {
                memmove(IndependentPages,
                        (const void *)(*(_QWORD *)(v10 + 24) & 0xFFFFFFFFFFFFF000ULL),
                        v16);

                v14 = SkciValidateImageData(
                        *(_QWORD *)(a1 + 136), v18, v16,
                        (unsigned int)(a4 >> 12), a6);

                if ( v14 < 0 )
                {
                    SkmmFreeIndependentPages(v18, v16);
                }
                else
                {
                    v19  = a9;
                    *v9  = &v18[*(unsigned int *)(v10 + 44)];
                    *v11 = v16;
                    if ( v19 )
                        *v19 = *(unsigned int *)(v10 + 40);
                }
            }
            else
            {
                v14 = -1073741670;
            }
        }
        else
        {
            SKMI_SECURITY(52LL);
            v14 = -1073741819;
        }
    }

    if ( v10 )
        SkmmUnmapDataTransfer(v10);

    return (unsigned int)v14;
}
```

The condition `(!a5 || *(_DWORD *)(a7 + 40) == a5)` with `a5 = 0`, the second operand never evaluates. The size check is skipped entirely. `v16` is computed as `PAGE_ALIGN_UP(page_offset + *(uint*)(mdl+40))`, where `*(uint*)(mdl+40)` is the size field from the MDL that VTL 0 provided. `v16` goes straight into `SkmmAllocateIndependentPages`.

## SkmmAllocateIndependentPages

```c
unsigned __int64 __fastcall SkmmAllocateIndependentPages(unsigned __int64 a1)
{
    unsigned __int64 v2;
    unsigned __int64 v3;
    unsigned __int64 v4;
    // ...

    v2 = (a1 >> 12) + ((a1 & 0xFFF) != 0);
    v3 = SkmmReserveMappingAddress(a1);
    v4 = v3;

    if ( v3 )
    {
        v6 = ((v3 >> 9) & 0x7FFFFFFFF8LL) - 0x98000000000LL;
        v7 = 0;
        // ...
        while ( 1 )
        {
            if ( v7 >= v2 )
                return v4;
            if ( !(unsigned int)SkmiAllocateSinglePage(0LL, &v23) )
                break;
            // PTE setup ...
            ++v7;
        }

        if ( v7 )
            SkmiFreeMappedPages(..., v7);
        SkmmFreeReservedMapping(v4, a1);
    }

    return 0LL;
}
```

First line: `v2 = (a1 >> 12) + ((a1 & 0xFFF) != 0)`. Byte count to pages, ceiling division. Then it enters a loop calling `SkmiAllocateSinglePage` once per page. No maximum. No quota check before the loop. `a1` comes directly from the `v16` computed in `SkmiCaptureAndValidateImageData`, which came from VTL 0.

## Back to the case 28 handler: the second memmove

After `SkmiCaptureAndValidateImageData` returns, back in case 28:

```c
v415 = (unsigned __int64)v612;   // IndependentPages

if ( v621 == *((_DWORD *)v612 + 1) )
{
    v416 = (void *)SkAllocatePool(512LL, v621, 1346923849LL);
    if ( v416 )
    {
        memmove(v416, (const void *)v415, *(unsigned int *)(v415 + 4));
        *((_QWORD *)v412 + 20) = v417;
    }
}
```

`v621` is the value returned via `a9` from `SkmiCaptureAndValidateImageData` specifically `*(uint*)(mdl+40)`, the size field from the MDL. `*((_DWORD *)v612 + 1)` is `IndependentPages[4]`, a field inside the buffer that was just copied from VTL 0.

VTL 0 controls both. Setting `SECURE_CALL_ARGS[4] = X` and writing `X` at offset 4 in the buffer it sends makes `v621 == IndependentPages[4]` evaluate to true. `SkAllocatePool` allocates `v621` bytes, then `memmove` copies `*(uint*)(IndependentPages+4)` bytes same value into that pool buffer.

## What this needs

I hit a nested virtualization limitation in my current setup that blocked the SkBridge lab I'd need for proper dynamic testing. Without that, the analysis stays static, and there are two things I can't confirm from static analysis alone.

One: whether `SkciValidateImageData` called inside `SkmiCaptureAndValidateImageData` after the allocation imposes constraints that would break the chain for arbitrary inputs. The function gets `v18`, `v16`, and a hash. If it rejects the data, the allocation gets freed and we never reach the second `memmove`. I traced the call far enough to see it's feeding into CI validation logic via `g_CiVslHvciInterface`, but the interface is populated via function pointer from `ci.dll` at runtime, which I'd need to trace separately.

Two: exact behavior of `SkmiAllocateSinglePage` under pressure. The loop in `SkmmAllocateIndependentPages` breaks cleanly if it fails, but what happens when you call it asking for a few thousand pages from the Secure Kernel's allocator is something I haven't tested.

The bit `0x20` guard at the top of case 28 is also worth understanding better. That bit isn't set anywhere in the case 25 code path I traced the Hex-Rays output doesn't show it being set in `SkmmCreateSecureImageSection`. Which means something else sets it, and `SkciCreateSecureImage` (via `g_CiVslHvciInterface`) is the likely candidate. If that path always validates the PE and always sets the bit after a clean validation, then arbitrary-sized input that survives `SkciValidateImageData` probably has to be at least a structurally valid PE which narrows the input space considerably.

That's where the research is right now. Nested virtualization sorted and dynamic testing is the next step. If you've done VTL 1 debugging before and have a working setup, I'd be curious to compare notes.
