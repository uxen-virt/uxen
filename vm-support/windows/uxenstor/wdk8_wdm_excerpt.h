#ifndef _WDK8_WDM_EXCERPT_H_
#define _WDK8_WDM_EXCERPT_H_

#include <no_sal2.h>

typedef volatile LONG EX_SPIN_LOCK, *PEX_SPIN_LOCK;
#define ALIGNED_EX_SPINLOCK DECLSPEC_CACHEALIGN EX_SPIN_LOCK

#if (NTDDI_VERSION >= NTDDI_VISTASP1)

_IRQL_requires_min_(DISPATCH_LEVEL)
VOID
ExAcquireSpinLockSharedAtDpcLevel (
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_)
    PEX_SPIN_LOCK SpinLock
    );

_IRQL_saves_
_IRQL_raises_(DISPATCH_LEVEL)
KIRQL
ExAcquireSpinLockShared (
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_)
    PEX_SPIN_LOCK SpinLock
    );

_IRQL_requires_min_(DISPATCH_LEVEL)
VOID
ExReleaseSpinLockSharedFromDpcLevel (
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
    PEX_SPIN_LOCK SpinLock
    );

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ExReleaseSpinLockShared (
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
    PEX_SPIN_LOCK SpinLock,
    _In_ _IRQL_restores_ KIRQL OldIrql
    );

_Must_inspect_result_
_IRQL_requires_(DISPATCH_LEVEL)
_Post_satisfies_(return == 0 || return == 1)
LOGICAL
ExTryConvertSharedSpinLockExclusive (
    _Inout_ PEX_SPIN_LOCK SpinLock
    );

_IRQL_requires_min_(DISPATCH_LEVEL)
VOID
ExAcquireSpinLockExclusiveAtDpcLevel (
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_)
    PEX_SPIN_LOCK SpinLock
    );

_IRQL_saves_
_IRQL_raises_(DISPATCH_LEVEL)
KIRQL
ExAcquireSpinLockExclusive (
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_)
    PEX_SPIN_LOCK SpinLock
    );

_IRQL_requires_min_(DISPATCH_LEVEL)
VOID
ExReleaseSpinLockExclusiveFromDpcLevel (
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
    PEX_SPIN_LOCK SpinLock
    );

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ExReleaseSpinLockExclusive (
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
    PEX_SPIN_LOCK SpinLock,
    _In_ _IRQL_restores_ KIRQL OldIrql
    );

#endif

#endif /* _WDK8_WDM_EXCERPT_H_ */