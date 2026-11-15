//! `keryx`: the CLI an agent shells out to, and the wrapper that gives it an
//! identity.
//!
//! Two audiences share one binary:
//!
//! - **Agents** use `post`, `read`, `subscribe`, and `whoami`. These only work
//!   inside a process launched by `keryx run`, because that is what supplies
//!   the identity.
//! - **Operators** use `keygen` and `run`.
//!
//! ```text
//! keryx keygen eng-01                     # once, to register an identity
//! keryx run --identity eng-01 -- claude   # launch an agent with that identity
//! #   inside that agent:
//!   keryx post general "starting"
//!   keryx read general --since 0
//!   keryx subscribe general
//! ```

mod cli;

use cli::clamp_code;

fn main() -> std::process::ExitCode {
    // clap parse of the 41-variant Command enum creates a ~1-2 MB stack frame
    // in debug builds, which overflows the default 1 MB Windows stack. Run the
    // whole CLI on an explicitly sized thread instead of relying on a linker
    // /STACK flag. The flag is removed from .cargo/config.toml.
    let handle = std::thread::Builder::new()
        .name("keryx-main".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| cli::run())
        .expect("spawn keryx-main thread");
    match handle.join().expect("keryx-main thread panicked") {
        Ok(code) => std::process::ExitCode::from(clamp_code(code)),
        Err(e) => {
            eprintln!("keryx: {e}");
            std::process::ExitCode::from(clamp_code(1))
        }
    }
}
