//! `Secret` and the types holding it are not `Clone`, are zeroized on drop and never print their
//! content. The "not Clone" checks are compile-time: if one of these types gains `Clone`, this
//! file stops compiling (the same technique as `static_assertions::assert_not_impl_any!`).

use hx_provision::{Action, ExecRequest, Secret, Secrets};
use zeroize::ZeroizeOnDrop;

/// `<T as AmbiguousIfClone<_>>::method` is ambiguous (a compile error) exactly when `T: Clone`.
trait AmbiguousIfClone<A> {
    fn method() {}
}
impl<T: ?Sized> AmbiguousIfClone<()> for T {}
impl<T: Clone> AmbiguousIfClone<u8> for T {}

macro_rules! assert_not_clone {
    ($($t:ty),+ $(,)?) => { $( let _ = <$t as AmbiguousIfClone<_>>::method; )+ };
}

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn secret_types_are_not_clone() {
    assert_not_clone!(Secret, Secrets, ExecRequest, Action);
}

#[test]
fn secret_types_zeroize_on_drop() {
    assert_zeroize_on_drop::<Secret>();
    assert_zeroize_on_drop::<Secrets>();
}

#[test]
fn debug_never_shows_the_bytes() {
    let s = Secret::from_slice(b"hunter2-hunter2");
    let shown = format!("{s:?}");
    assert!(!shown.contains("hunter2"), "{shown}");
    let secrets = Secrets::none()
        .with_user_password("hunter2-hunter2")
        .unwrap();
    assert!(!format!("{secrets:?}").contains("hunter2"));
}

#[test]
fn equality_is_the_non_branching_fold_not_a_derive() {
    let a = Secret::from_slice(b"correct horse");
    assert!(a == Secret::from_slice(b"correct horse"));
    assert!(a != Secret::from_slice(b"Correct horse"), "first byte");
    assert!(a != Secret::from_slice(b"correct horsf"), "last byte");
    assert!(a != Secret::from_slice(b"correct hors"), "length");
    assert!(Secret::from_slice(b"") == Secret::from_slice(b""));
    // No derived PartialEq (a derive would compare with an early exit).
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/exec.rs")).unwrap();
    let at = src.find("pub struct Secret(").unwrap();
    let before = &src[..at];
    let attrs = before.rsplit("\n\n").next().unwrap();
    assert!(!attrs.contains("PartialEq"), "{attrs}");
}
