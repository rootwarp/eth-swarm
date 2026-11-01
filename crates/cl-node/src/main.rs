//! `cl-node`: see [`cl_node::cli::USAGE`].

use std::process::ExitCode;

use cl_node::cli::{parse, write_units, Command, USAGE};
use cl_node::units::generate;

fn main() -> ExitCode {
    let result = match parse(std::env::args_os().skip(1)) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            Ok(())
        }
        Ok(Command::Units { out, config }) => {
            write_units(&out, &generate(&config)).map_err(|e| e.to_string())
        }
        #[cfg(target_os = "linux")]
        Ok(Command::Launch(launch)) => cl_node::launch::run(&launch),
        #[cfg(not(target_os = "linux"))]
        Ok(Command::Launch(_)) => Err("launch runs on Linux only".into()),
        Err(e) => {
            eprintln!("cl-node: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cl-node: {e}");
            ExitCode::FAILURE
        }
    }
}
