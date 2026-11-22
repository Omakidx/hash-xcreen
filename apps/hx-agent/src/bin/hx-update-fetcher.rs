//! hx-update-fetcher: the sandboxed downloader of the self-update path and of the prebuilt-image
//! path (docs/ipc.md 6.12).
//!
//! Started by `hx-update-fetcher@<job>.service` (update jobs: `manifest-stable`, `manifest-beta`,
//! `artifact-<version>`) or by `hx-image-fetcher@<job>.service` (image jobs: `images-manifest`,
//! `probe-<recipe>-<build_id>`, `image-<recipe>-<build_id>-<nparts>`), both with a dynamic user, no
//! capabilities and no `AF_UNIX`. The one argument is the job, the unit's instance name. The image
//! unit sets `HX_FETCH_TEMPLATE=image`; an image job under the update template and an update job
//! under the image template are refused (exit 2). It downloads bytes into the unit's bind-mounted
//! directory and exits 0; it verifies nothing. Everything else is `hx_agent::fetcher`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use hx_agent::fetcher::images::TEMPLATE_ENV;
use hx_agent::fetcher::{Config, ImageJob, Job, Template, run, run_image};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(arg), None) = (args.next(), args.next()) else {
        eprintln!("hx-update-fetcher: expected exactly one job argument");
        return ExitCode::from(2);
    };
    let template = match std::env::var(TEMPLATE_ENV) {
        Ok(v) => Template::from_env_value(Some(&v)),
        Err(std::env::VarError::NotPresent) => Template::from_env_value(None),
        Err(_) => None,
    };
    let Some(template) = template else {
        eprintln!("hx-update-fetcher: unknown fetcher template");
        return ExitCode::from(2);
    };
    let Some(instance) = arg.to_str() else {
        eprintln!("hx-update-fetcher: not a valid job");
        return ExitCode::from(2);
    };
    match template {
        Template::Update => {
            let Some(job) = Job::parse(instance) else {
                eprintln!("hx-update-fetcher: not a valid job for the update template");
                return ExitCode::from(2);
            };
            let cfg = match Config::production() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("hx-update-fetcher: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match run(&job, &cfg) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("hx-update-fetcher: {} failed: {e}", job.instance());
                    ExitCode::FAILURE
                }
            }
        }
        Template::Image => {
            let Some(job) = ImageJob::parse(instance) else {
                eprintln!("hx-update-fetcher: not a valid job for the image template");
                return ExitCode::from(2);
            };
            let cfg = match Config::production_image() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("hx-update-fetcher: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match run_image(&job, &cfg) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("hx-update-fetcher: {} failed: {e}", job.instance());
                    ExitCode::FAILURE
                }
            }
        }
    }
}
