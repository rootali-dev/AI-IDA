//! AI-IDA — برنامه XDP/eBPF در Kernel Space
//!
//! منطق: پکت‌های IPv4/UDP را DROP کن، بقیه را PASS بده.
//! تمام دسترسی‌ها به حافظه پکت با bounds checking محافظت شده‌اند.

// غیرفعال کردن کتابخانه استاندارد؛ در eBPF فقط no_std مجاز است
#![no_std]
// نقطه ورود main معمولی نداریم؛ ورود از ماکرو #[xdp] است
#![no_main]

// import ماکرو و تایپ‌های Aya برای برنامه XDP
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
// import ساختارهای هدر شبکه (Ethernet و IPv4)
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

// ثابت: طول هدر اترنت استاندارد (۱۴ بایت، بدون VLAN)
const ETH_HDR_LEN: usize = EthHdr::LEN;
// ثابت: حداقل طول هدر IPv4 (۲۰ بایت، بدون options)
const IPV4_HDR_MIN_LEN: usize = Ipv4Hdr::LEN;

/// نقطه ورود XDP — کرنل برای هر پکت ورودی این تابع را صدا می‌زند.
#[xdp]
pub fn ai_ida_xdp(ctx: XdpContext) -> u32 {
    // منطق اصلی را جدا می‌کنیم تا خطاها را تمیز handle کنیم
    match try_ai_ida_xdp(ctx) {
        // اگر موفق بود، همان XDP_PASS یا XDP_DROP برگردان
        Ok(action) => action,
        // خطای پارس/مرز حافظه → ABORTED (پکت discard، بدون crash کرنل)
        Err(()) => xdp_action::XDP_ABORTED,
    }
}

/// منطق فیلتر: پارس Ethernet → بررسی IPv4 → DROP اگر UDP
fn try_ai_ida_xdp(ctx: XdpContext) -> Result<u32, ()> {
    // ── مرحله ۱: Bounds check برای هدر Ethernet ──
    // offset=0 یعنی ابتدای buffer پکت؛ ptr_at قبل از dereference چک می‌کند
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    // ether_type() نوع لایه ۳ را برمی‌گرداند (IPv4، ARP، IPv6، ...)
    match unsafe { (*ethhdr).ether_type() } {
        // فقط IPv4 را فیلتر می‌کنیم؛ بقیه بدون دستکاری PASS می‌شوند
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // ── مرحله ۲: Bounds check برای هدر IPv4 ──
    // هدر IP بلافاصله بعد از Ethernet شروع می‌شود (offset = 14)
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, ETH_HDR_LEN)?;

    // بررسی نسخه IP: ۴ بیت بالای version_ihl باید 4 باشد (IPv4)
    let version = unsafe { (*ipv4hdr).version_ihl >> 4 };
    if version != 4 {
        // نسخه غیرمنتظره → امن‌ترین کار PASS است
        return Ok(xdp_action::XDP_PASS);
    }

    // IHL = طول واقعی هدر IP بر حسب ۳۲-bit word (×4 = بایت)
    let ihl_words = (unsafe { (*ipv4hdr).version_ihl } & 0x0F) as usize;
    let ip_hdr_len = ihl_words.checked_mul(4).ok_or(())?;

    // هدر IP نمی‌تواند از حداقل ۲۰ بایت کوچک‌تر باشد (RFC 791)
    if ip_hdr_len < IPV4_HDR_MIN_LEN {
        return Err(());
    }

    // مطمئن شو کل هدر IP (شامل options) داخل buffer پکت جا می‌شود
    bounds_check(&ctx, ETH_HDR_LEN, ip_hdr_len)?;

    // ── مرحله ۳: تصمیم فیلتر بر اساس پروتکل L4 ──
    let protocol = unsafe { (*ipv4hdr).proto };

    if protocol == IpProto::Udp {
        // UDP → DROP (هدف اصلی فایروال AI-IDA در این نمونه)
        Ok(xdp_action::XDP_DROP)
    } else {
        // TCP، ICMP، و غیره → PASS
        Ok(xdp_action::XDP_PASS)
    }
}

/// بررسی مرز حافظه: آیا `[data+offset .. data+offset+len)` داخل پکت است؟
///
/// Verifier لینوکس این الگو را می‌شناسد: `start + offset + len > end`
/// یعنی هر byte که می‌خواهیم بخوانیم، قبلش ثابت شده داخل buffer است.
#[inline(always)]
fn bounds_check(ctx: &XdpContext, offset: usize, len: usize) -> Result<(), ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    if start + offset + len > end {
        return Err(());
    }

    Ok(())
}

/// گرفتن pointer امن به struct در offset مشخص داخل پکت
///
/// Verifier برای هر `*const T` باید proof داشته باشد که
/// تمام `size_of::<T>()` بایت در محدوده `[data, data_end)` هستند.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    // ★ حیاتی: بدون این if، verifier برنامه را REJECT می‌کند
    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// Panic handler الزامی در no_std — در eBPF panic نباید unwind کند
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
