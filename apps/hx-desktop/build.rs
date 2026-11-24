fn main() {
    // `MouseCursor.custom` (the remote pointer shape as the system pointer, architecture 6.3)
    // is an experimental Slint language feature; Slint is pinned to one exact version, so it
    // cannot change under us (tech-stack.md). The compiler reads the list from this variable.
    const FEATURE: &str = "custom-mouse-cursor";
    let features = match std::env::var("SLINT_ENABLE_EXPERIMENTAL_FEATURES") {
        Ok(list) if list.split(',').any(|f| f.trim() == FEATURE) => list,
        Ok(list) if !list.trim().is_empty() => format!("{list},{FEATURE}"),
        _ => FEATURE.to_owned(),
    };
    // SAFETY: a build script is single-threaded here: nothing else reads the environment.
    unsafe { std::env::set_var("SLINT_ENABLE_EXPERIMENTAL_FEATURES", features) };

    // Debug builds carry element debug info so the screen tests can find elements by their
    // accessible names (the Slint testing backend needs it); release builds do not.
    let debug = std::env::var("PROFILE").is_ok_and(|p| p == "debug");
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent".into())
        .with_debug_info(debug);
    slint_build::compile_with_config("ui/app.slint", config).expect("compile the Slint UI");
}
