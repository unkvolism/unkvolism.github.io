I had no plans to write about CPUID this week. The whole thing started as a Rust exercise. I wanted to practice the `bitflags` crate on something real, and a friend suggested porting a small C tool I'd written months ago that dumps Hyper-V's synthetic CPUID leaves. Easy, contained, mechanical.

By the end of the day I had a working dumper and three undocumented bits I can't explain. This post is about how that happened and what I think they might be.

## The boring part: what synthetic CPUID leaves are

Quick refresher in case you don't live in hypervisor internals. When a hypervisor is present, the `CPUID` instruction with `EAX` in the range `0x40000000`–`0x400000FF` doesn't query the physical CPU it queries the hypervisor. Microsoft uses this range to expose Hyper-V's identity, capabilities, partition privileges, hardware features it's using, and so on. The full spec lives in the Hyper-V TLFS (Top-Level Functional Specification), which used to be a PDF and now lives on Microsoft Learn.

The TLFS publicly documents leaves `0x40000000` through `0x4000000A`. Two of these I find especially interesting:

- **`0x40000003`** carries the partition privilege flags what the current partition is allowed to do. Reading this tells you whether you're in the root partition or a child, and which subset of hypercalls/MSRs you can touch.
- **`0x40000006`** reports which hardware features the hypervisor is using. SLAT, APIC overlay, DMA protection, interrupt remapping, that sort of thing.

These are normally accessed by `nt!HvlpInitializeCpuid` and similar functions at boot, but any usermode program can query them too. There's no privilege check on `CPUID`.

## The Rust exercise

The original C dumper I had was fine but ugly lots of manual `& (1 << N)` tests and `printf` for each flag. The Rust version was supposed to clean that up using `bitflags`, which lets you define a typed set of bit constants and iterate over which ones are set in a value. The output is much nicer:

```
[#] Hardware Features (EAX, raw: 0x09F200AF):
  [+] HardwareFeaturesEax(APIC_OVERLAY_ASSIST)
  [+] HardwareFeaturesEax(MSR_BITMAPS)
  [+] HardwareFeaturesEax(SLAT)
  ...
```

I built it up leaf by leaf first the parser, then a `bitflags` struct for partition privilege flags (`AccessVpRunTimeReg`, `AccessSynicRegs`, all that), then more `bitflags` for the hardware features, and so on. Mechanical work.

Somewhere along the way I added a small thing that turned out to matter: any time I applied a `bitflags` to a value, I'd also compute the bits in the value that *weren't* in my table the "unknown bits". The logic is one line:

```rust
let known_bits = features.bits();
let unknown_bits = regs.eax & !known_bits;
```

If `unknown_bits != 0`, the dumper prints them. This was meant as a defensive thing if Microsoft adds new flags in future builds, I'd see something rather than silently truncating.

## The moment

I ran the dumper on my own machine. Windows 11 Pro 25H2, OS Build 26200.8246. Output for the hardware features leaf:

```
=== CPUID 0x40000006 - HardwareFeatures ===
Raw: EAX=09F200AF EBX=00000027 ECX=00000000 EDX=00000000

[#] Hardware Features (EAX, raw: 0x09F200AF):
  [+] HardwareFeaturesEax(APIC_OVERLAY_ASSIST)
  [+] HardwareFeaturesEax(MSR_BITMAPS)
  [+] HardwareFeaturesEax(ARCHITECTURAL_PERF_COUNTERS)
  [+] HardwareFeaturesEax(SLAT)
  [+] HardwareFeaturesEax(INTERRUPT_REMAPPING)
  [+] HardwareFeaturesEax(DMA_PROTECTION)

[?] Unknown bits set: 0x09F20000
  EBX (undocumented): 0x00000027
```

Two things stood out:

1. `EAX` has bits set above bit 9, which is where the public TLFS list ends. Specifically bits 17, 21, 25, 27.
2. `EBX` is documented as reserved. Mine isn't. It's `0x00000027` bits 0, 1, 2, 5.

I went and double-checked the TLFS to make sure I hadn't missed something. Microsoft's `HV_HYPERVISOR_HARDWARE_FEATURES` structure (you can find it on Microsoft Learn) really does only document bits 0–9 of the equivalent of `EAX`, and treats `EBX` as reserved.

So I'm seeing five bits across two registers that the spec doesn't explain. Cool.

## What I don't know

I'll be upfront: I haven't reverse engineered `hvix64.exe` to confirm what these bits mean. This post is observation, not explanation. But I want to be honest about the speculation while keeping it speculation.

For `EAX` bits 17, 21, 25, 27, the candidates I'd look at first if I were going to reverse this:

- **MBEC** (Mode-Based Execute Control). The TLFS mentions MBEC support in the context of VBS but doesn't give it a bit in this leaf publicly. It would make sense to advertise it here.
- **kCFG hardware acceleration**. Windows uses both software (`KiCfgBitmap`) and hardware-assisted CFG. The latter goes through `HvlUpdateCfg` hypercalls.
- **CET shadow stack support** at the hypervisor level. Hyper-V has to coordinate with CET when running guests.
- **Newer VBS isolation primitives** added in 24H2/25H2 (the kernel still reports build 26100 even though the OS build is 26200, because 25H2 is an enablement package on top of 24H2).

`EBX = 0x27` is harder to guess at without more context. The fact that it's a small number with a specific bit pattern (`0010 0111`) suggests it's not noise something is deliberately setting these bits. My instinct is that this is a secondary feature register that Microsoft just hasn't bothered to document publicly. It happens.

## Leaves past the documented range

While I was at it, I noticed something else. The hypervisor reports `max_leaf = 0x4000000C` but the public TLFS only goes up to `0x4000000A`. So the hypervisor is advertising the existence of `0x4000000B` and `0x4000000C`.

Both return all zeros on my machine.

That doesn't mean they're empty. There are at least three reasons a CPUID leaf might return zero on a given host:

1. The slot is reserved and the handler doesn't populate anything yet.
2. The handler is conditional only populates if certain hypercalls have been made, or if the partition has certain privileges, or if you're inside an isolated VM (SEV-SNP / TDX).
3. The handler depends on hardware that isn't present on this CPU.

Distinguishing (1) from (2) and (3) requires looking at `hvix64.exe` itself. Worth doing one day; not today.

## Why bother documenting this

Two reasons.

One, it's the kind of thing that's easy to spot but boring to write up, so it tends to not get written up. The bits have probably been observed by other people staring at CPUID dumps over the years; they just didn't post about it. By writing this I'm hoping to surface something that lets someone with more context (or more time to reverse engineer) connect the dots.

Two, undocumented CPUID bits are a useful starting point for finding new features. Every feature that exists in the hypervisor had to be checked for somewhere either at boot, when initializing capabilities, or at the moment a hypercall is made. Tracing back from a bit to the code that sets it is one of the cleaner ways to find a feature's implementation. If any of these bits turn out to be VBS-related, that's directly relevant to research I care about.

## The Rust angle

If you're more interested in the language than the hypervisor, the project is a small but pretty good example of `bitflags`, `enum` with `#[repr(u32)]` discriminants, `TryFrom` implementation, exhaustive `match`, and modularization across multiple files. The whole dumper is around 350 lines split into `cpuid.rs`, `flags.rs`, `decoders.rs`, `leaf.rs`, and `main.rs`.

The "unknown bits" trick is the only non-obvious idiom in there. `bitflags!` gives you `from_bits_truncate` which silently drops unknown bits defensive, but it loses information. Adding three lines to compute and print the dropped bits costs nothing and means the tool will keep being useful as Microsoft adds new flags.

```rust
let features = HardwareFeaturesEax::from_bits_truncate(regs.eax);
let known_bits = features.bits();
let unknown_bits = regs.eax & !known_bits;

if unknown_bits != 0 {
    println!("[?] Unknown bits set: 0x{:08X}", unknown_bits);
}
```

That's it. The next time I run this on a Canary build or a different Hyper-V configuration, the same line will tell me if anything new appeared.

## Where to find it

Source code: [github.com/unkvolism/hv_cpuid_dump](https://github.com/unkvolism/hv_cpuid_dump)
<br>
Hyper-V TLFS (Top-Level Functional Specification): [Docs](https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/master/tlfs/Hypervisor%20Top%20Level%20Functional%20Specification%20v5.0.pdf)

If you reproduce different output on a different Windows build or Hyper-V config, I'd love to see it. Drop a note on Twitter (@ExallocatePool2) or open an issue on the repo.

If you happen to know what bits 17/21/25/27 of `EAX` in `0x40000006` mean, please tell me.

---

*Tested on: Windows 11 Pro 25H2, OS Build 26200.8246 (kernel reports build 26100, since 25H2 is an enablement package on top of 24H2). Intel x86_64, Hyper-V/VBS enabled, root partition.*