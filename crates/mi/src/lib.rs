//! GDB/MI3 protocol support: output parser and an async session over a spawned gdb.

mod connection;
mod lines;
mod parser;

pub use connection::{Event, Gdb, GdbOptions, MiError, MiResult, quote};
pub use lines::LineBuffer;
pub use parser::{AsyncKind, ParseError, Record, ResultClass, StreamKind, Tuple, Value, parse_line, parse_result_prefix};
