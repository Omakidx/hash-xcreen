//! `hx-pwcheck <login>`: see the library documentation for the contract.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // An argument that is not UTF-8 cannot be a login name the caller validated: usage error.
    let args: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect();
    let Ok(args) = args else {
        eprintln!("hx-pwcheck: arguments must be UTF-8");
        return ExitCode::from(hx_pwcheck::EXIT_USAGE);
    };
    ExitCode::from(hx_pwcheck::run(&args, std::io::stdin().lock()))
}
