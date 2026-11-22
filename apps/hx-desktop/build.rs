fn main() {
    // Debug builds carry element debug info so the screen tests can find elements by their
    // accessible names (the Slint testing backend needs it); release builds do not.
    let debug = std::env::var("PROFILE").is_ok_and(|p| p == "debug");
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent".into())
        .with_debug_info(debug);
    slint_build::compile_with_config("ui/app.slint", config).expect("compile the Slint UI");
}
