# BPF VM lives in pktbaffle, not pkttap

pktbaffle is a compiler; adding a runtime (the VM) expands its scope. We put it there anyway, behind an optional `vm` feature, because the VM evaluates a `Program` — a type pktbaffle owns — against raw bytes. Putting the VM in `pkttap` would either require exposing pktbaffle internals or duplicating the instruction encoding. Any caller that wants software filtering without pulling in `pkttap` also benefits.
