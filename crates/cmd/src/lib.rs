//! x64dbg command-bar syntax: expressions and commands, translated for gdb.

mod command;
mod expr;
mod log;
mod script;

pub use command::{Command, HardwareAccess, SearchScope, parse_command};
pub use expr::{ExprError, Resolver, looks_like_expression, translate_assignment, translate_expression};
pub use log::translate_log_text;
pub use script::{Script, ScriptError, ScriptStep};
