//! `hx-imagectl`: the image CI tool. See the library docs for the commands.

fn main() -> std::process::ExitCode {
    hx_imagectl::main_with_args(std::env::args().skip(1).collect())
}
