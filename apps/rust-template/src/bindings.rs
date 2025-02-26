// Generated by `wit-bindgen` 0.36.0. DO NOT EDIT!
// Options used:
//   * runtime_path: "wit_bindgen_rt"
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_register_routes_cabi<T: Guest>() {
    #[cfg(target_arch = "wasm32")] _rt::run_ctors_once();
    T::register_routes();
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_load_from_ledger_cabi<T: Guest>(arg0: *mut u8, arg1: usize) {
    #[cfg(target_arch = "wasm32")] _rt::run_ctors_once();
    let len0 = arg1;
    let bytes0 = _rt::Vec::from_raw_parts(arg0.cast(), len0, len0);
    T::load_from_ledger(_rt::string_lift(bytes0));
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_insert_in_ledger_cabi<T: Guest>(arg0: *mut u8, arg1: usize) {
    #[cfg(target_arch = "wasm32")] _rt::run_ctors_once();
    let len0 = arg1;
    let bytes0 = _rt::Vec::from_raw_parts(arg0.cast(), len0, len0);
    T::insert_in_ledger(_rt::string_lift(bytes0));
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_ping_cabi<T: Guest>(arg0: *mut u8, arg1: usize) {
    #[cfg(target_arch = "wasm32")] _rt::run_ctors_once();
    let len0 = arg1;
    let bytes0 = _rt::Vec::from_raw_parts(arg0.cast(), len0, len0);
    T::ping(_rt::string_lift(bytes0));
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_ping2_cabi<T: Guest>() {
    #[cfg(target_arch = "wasm32")] _rt::run_ctors_once();
    T::ping2();
}
pub trait Guest {
    fn register_routes();
    fn load_from_ledger(cmd: _rt::String);
    fn insert_in_ledger(cmd: _rt::String);
    fn ping(cmd: _rt::String);
    fn ping2();
}
#[doc(hidden)]
macro_rules! __export_world_rust_template_cabi {
    ($ty:ident with_types_in $($path_to_types:tt)*) => {
        const _ : () = { #[export_name = "register-routes"] unsafe extern "C" fn
        export_register_routes() { $($path_to_types)*::
        _export_register_routes_cabi::<$ty > () } #[export_name = "load-from-ledger"]
        unsafe extern "C" fn export_load_from_ledger(arg0 : * mut u8, arg1 : usize,) {
        $($path_to_types)*:: _export_load_from_ledger_cabi::<$ty > (arg0, arg1) }
        #[export_name = "insert-in-ledger"] unsafe extern "C" fn
        export_insert_in_ledger(arg0 : * mut u8, arg1 : usize,) { $($path_to_types)*::
        _export_insert_in_ledger_cabi::<$ty > (arg0, arg1) } #[export_name = "ping"]
        unsafe extern "C" fn export_ping(arg0 : * mut u8, arg1 : usize,) {
        $($path_to_types)*:: _export_ping_cabi::<$ty > (arg0, arg1) } #[export_name =
        "ping2"] unsafe extern "C" fn export_ping2() { $($path_to_types)*::
        _export_ping2_cabi::<$ty > () } };
    };
}
#[doc(hidden)]
pub(crate) use __export_world_rust_template_cabi;
#[rustfmt::skip]
mod _rt {
    #[cfg(target_arch = "wasm32")]
    pub fn run_ctors_once() {
        wit_bindgen_rt::run_ctors_once();
    }
    pub use alloc_crate::vec::Vec;
    pub unsafe fn string_lift(bytes: Vec<u8>) -> String {
        if cfg!(debug_assertions) {
            String::from_utf8(bytes).unwrap()
        } else {
            String::from_utf8_unchecked(bytes)
        }
    }
    pub use alloc_crate::string::String;
    extern crate alloc as alloc_crate;
}
/// Generates `#[no_mangle]` functions to export the specified type as the
/// root implementation of all generated traits.
///
/// For more information see the documentation of `wit_bindgen::generate!`.
///
/// ```rust
/// # macro_rules! export{ ($($t:tt)*) => (); }
/// # trait Guest {}
/// struct MyType;
///
/// impl Guest for MyType {
///     // ...
/// }
///
/// export!(MyType);
/// ```
#[allow(unused_macros)]
#[doc(hidden)]
macro_rules! __export_rust_template_impl {
    ($ty:ident) => {
        self::export!($ty with_types_in self);
    };
    ($ty:ident with_types_in $($path_to_types_root:tt)*) => {
        $($path_to_types_root)*:: __export_world_rust_template_cabi!($ty with_types_in
        $($path_to_types_root)*);
    };
}
#[doc(inline)]
pub(crate) use __export_rust_template_impl as export;
#[cfg(target_arch = "wasm32")]
#[link_section = "component-type:wit-bindgen:0.36.0:component:rust-template:rust-template:encoded world"]
#[doc(hidden)]
pub static __WIT_BINDGEN_COMPONENT_TYPE: [u8; 276] = *b"\
\0asm\x0d\0\x01\0\0\x19\x16wit-component-encoding\x04\0\x07\x90\x01\x01A\x02\x01\
A\x07\x01@\0\x01\0\x04\0\x0fregister-routes\x01\0\x01@\x01\x03cmds\x01\0\x04\0\x10\
load-from-ledger\x01\x01\x04\0\x10insert-in-ledger\x01\x01\x04\0\x04ping\x01\x01\
\x04\0\x05ping2\x01\0\x04\0%component:rust-template/rust-template\x04\0\x0b\x13\x01\
\0\x0drust-template\x03\0\0\0G\x09producers\x01\x0cprocessed-by\x02\x0dwit-compo\
nent\x070.220.1\x10wit-bindgen-rust\x060.36.0";
#[inline(never)]
#[doc(hidden)]
pub fn __link_custom_section_describing_imports() {
    wit_bindgen_rt::maybe_link_cabi_realloc();
}
