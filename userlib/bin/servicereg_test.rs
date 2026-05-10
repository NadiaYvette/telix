//! servicereg_test — self-test validating servicereg_srv + userlib::services.
//!
//! Exercises the full register / lookup / re-register / method-mask /
//! unregister cycle from a single process.  Runs through six scenarios
//! and reports PASS/FAIL per scenario plus an overall summary.  Exit
//! code 0 = all pass, 1 = any fail.
//!
//! Wire-up: add this binary to init.rs as a phase test, or run it
//! standalone after spawning servicereg_srv.

#![no_std]
#![no_main]

extern crate userlib;

use userlib::{services, syscall};

/// Test fixture UUID — arbitrary v4 random bytes for the validation.
/// Real services pick + publish their own UUIDs; this one is just a
/// self-test fixture and shouldn't conflict with anything else.
const TEST_UUID: services::ServiceUuid = [
    0x7e, 0x57, 0xfe, 0x57, 0x7e, 0x57, 0xfe, 0x57,
    0x7e, 0x57, 0xfe, 0x57, 0x7e, 0x57, 0xfe, 0x57,
];

/// A second UUID for the multi-service scenario.
const TEST_UUID_2: services::ServiceUuid = [
    0xa1, 0x1e, 0xa1, 0x1e, 0xa1, 0x1e, 0xa1, 0x1e,
    0xa1, 0x1e, 0xa1, 0x1e, 0xa1, 0x1e, 0xa1, 0x1e,
];

fn report(label: &[u8], pass: bool) -> bool {
    syscall::debug_puts(if pass { b"  [servicereg_test] PASS " } else { b"  [servicereg_test] FAIL " });
    syscall::debug_puts(label);
    syscall::debug_puts(b"\n");
    pass
}

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[servicereg_test] starting\n");

    // Wait for servicereg_srv to register itself in the nameserver
    // — we may be spawned alongside it.  ns_lookup_wait blocks
    // inside the kernel until the service appears.
    if syscall::ns_lookup_wait(b"servicereg").is_none() {
        let _ = report(b"servicereg_srv never registered", false);
        syscall::exit(1);
    }

    let mut all_pass = true;

    // Scenario 1: register a UUID with method-mask covering methods
    // 0, 1, 3 (mask = 0b1011 = 11), then look it up with method 0
    // and verify the resolved port matches.
    let svc_port_a = syscall::port_create();
    if svc_port_a == u64::MAX {
        let _ = report(b"port_create for service A", false);
        syscall::exit(1);
    }
    let mask_a: u64 = 0b1011;
    let ok = services::register(&TEST_UUID, mask_a, services::CAP_DEFAULT, svc_port_a);
    all_pass &= report(b"S1 register succeeded", ok);
    let r = services::lookup(&TEST_UUID, 0);
    all_pass &= report(
        b"S1 lookup(method=0) returns registered port",
        matches!(r, Some(ep) if ep.port == svc_port_a),
    );

    // Scenario 2: lookup with a method NOT in the mask — should
    // resolve to None (the registrant doesn't support method 2).
    let r = services::lookup(&TEST_UUID, 2);
    all_pass &= report(b"S2 lookup(unsupported method) returns None", r.is_none());

    // Scenario 3: lookup with a different method that IS in the mask
    // (method 3 is in 0b1011) — should resolve.
    let r = services::lookup(&TEST_UUID, 3);
    all_pass &= report(
        b"S3 lookup(method=3) resolves",
        matches!(r, Some(ep) if ep.port == svc_port_a),
    );

    // Scenario 4: re-registration with a different port + mask.
    // The UUID slot should update in place, not allocate a second
    // entry; the new port becomes authoritative.
    let svc_port_b = syscall::port_create();
    if svc_port_b == u64::MAX {
        let _ = report(b"port_create for service B", false);
        syscall::exit(1);
    }
    let mask_b: u64 = 0b0100; // only method 2 supported
    let ok = services::register(&TEST_UUID, mask_b, services::CAP_DEFAULT, svc_port_b);
    all_pass &= report(b"S4 re-register succeeded", ok);
    let r_old_method = services::lookup(&TEST_UUID, 0);
    all_pass &= report(
        b"S4 old method 0 no longer resolves after re-register",
        r_old_method.is_none(),
    );
    let r_new_method = services::lookup(&TEST_UUID, 2);
    all_pass &= report(
        b"S4 new method 2 resolves to new port",
        matches!(r_new_method, Some(ep) if ep.port == svc_port_b),
    );

    // Scenario 5: register a second distinct UUID alongside the
    // first.  Both should resolve independently, demonstrating that
    // the registry handles multiple concurrent entries.
    let svc_port_c = syscall::port_create();
    if svc_port_c == u64::MAX {
        let _ = report(b"port_create for service C", false);
        syscall::exit(1);
    }
    let ok = services::register(&TEST_UUID_2, u64::MAX, services::CAP_DEFAULT, svc_port_c);
    all_pass &= report(b"S5 register second UUID", ok);
    let r1 = services::lookup(&TEST_UUID, 2);
    let r2 = services::lookup(&TEST_UUID_2, 0);
    all_pass &= report(
        b"S5 both UUIDs resolve to their registered ports",
        matches!(r1, Some(ep) if ep.port == svc_port_b)
            && matches!(r2, Some(ep) if ep.port == svc_port_c),
    );

    // Scenario 6: unregister TEST_UUID; subsequent lookups return
    // None.  TEST_UUID_2 is unaffected.
    let ok = services::unregister(&TEST_UUID, svc_port_b);
    all_pass &= report(b"S6 unregister succeeded", ok);
    let r1 = services::lookup(&TEST_UUID, 2);
    all_pass &= report(b"S6 unregistered UUID lookup returns None", r1.is_none());
    let r2 = services::lookup(&TEST_UUID_2, 0);
    all_pass &= report(
        b"S6 untouched UUID still resolves",
        matches!(r2, Some(ep) if ep.port == svc_port_c),
    );

    // Scenario 7: capability bundle round-trip + attenuation (Piece c).
    // Re-register TEST_UUID_2 with a specific bundle, look it up,
    // verify the bundle is returned in capability_hint.  Then run
    // attenuate() against a narrowing mask and verify the result.
    let bundle_full = services::CAP_INVOKE | services::CAP_READ
        | services::CAP_WRITE | services::CAP_FORWARD
        | services::CAP_LOCAL_ONLY;
    let ok = services::register(&TEST_UUID_2, u64::MAX, bundle_full, svc_port_c);
    all_pass &= report(b"S7 register with full bundle", ok);
    let r = services::lookup(&TEST_UUID_2, 0);
    all_pass &= report(
        b"S7 lookup returns bundle in capability_hint",
        matches!(r, Some(ep) if ep.capability_hint == bundle_full),
    );
    // Attenuate: drop CAP_FORWARD + CAP_WRITE.  The result should
    // have CAP_INVOKE + CAP_READ + CAP_LOCAL_ONLY only.
    let narrowing = services::CAP_INVOKE | services::CAP_READ
        | services::CAP_LOCAL_ONLY;
    let attenuated = services::attenuate(bundle_full, narrowing);
    all_pass &= report(
        b"S7 attenuate yields strictly narrower bundle",
        attenuated == narrowing
            && attenuated & services::CAP_FORWARD == 0
            && attenuated & services::CAP_WRITE == 0,
    );

    // Final summary.
    if all_pass {
        syscall::debug_puts(b"[servicereg_test] PASSED (7 scenarios)\n");
        syscall::exit(0);
    } else {
        syscall::debug_puts(b"[servicereg_test] FAILED\n");
        syscall::exit(1);
    }
}
