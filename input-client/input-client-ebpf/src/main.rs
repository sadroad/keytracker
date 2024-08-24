#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, map}, maps:: RingBuf, programs::ProbeContext};

#[map(name = "EVENTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1024, 0);

#[repr(C)]
struct KeyEvent {
    key_type: u32,
    code: u32,
    value: u32,
}

#[kprobe]
pub fn input_client(ctx: ProbeContext) -> u32 {
    match try_input_client(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

const EV_KEY: u32 = 0x01;

fn try_input_client(ctx: ProbeContext) -> Result<u32, u32> {
    let key_type: u32 = ctx.arg(1).unwrap();
    let code: u32 = ctx.arg(2).unwrap();
    let value: u32 =  ctx.arg(3).unwrap();

    if key_type == EV_KEY {
        let event = KeyEvent {
            key_type,
            code,
            value,
        };

        unsafe {
            if let Some(mut buf) = EVENTS.reserve::<KeyEvent>(0) {
                buf.write(event);
                buf.submit(0);
            }
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
