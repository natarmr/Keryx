//! `idboard`: the CLI an agent shells out to, and the wrapper that gives it an
//! identity.
//!
//! Two audiences share one binary:
//!
//! - **Agents** use `post`, `read`, `subscribe`, and `whoami`. These only work
//!   inside a process launched by `idboard run`, because that is what supplies
//!   the identity.
//! - **Operators** use `keygen` and `run`.
//!
//! ```text
//! idboard keygen eng-01                     # once, to register an identity
//! idboard run --identity eng-01 -- claude   # launch an agent with that identity
//! #   inside that agent:
//!   idboard post general "starting"
//!   idboard read general --since 0
//!   idboard subscribe general
//! ```

mod cli;

use cli::clamp_code;

fn main() -> std::process::ExitCode {
    match cli::run() {
        Ok(code) => std::process::ExitCode::from(clamp_code(code)),
        Err(e) => {
            eprintln!("idboard: {e}");
            std::process::ExitCode::from(clamp_code(1))
        }
    }
}
