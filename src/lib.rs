//! A high-performance Mach-O linker.

pub mod arch;
pub mod cmdline;
pub mod context;
pub mod driver;
pub mod error;
pub mod filetype;
pub mod icf;
pub mod input_files;
pub mod input_sections;
pub mod lto;
pub mod macho;
pub mod mapfile;
pub mod mapped_file;
pub mod output_chunks;
pub mod output_file;
pub mod passes;
pub mod relocatable;
pub mod symbol;
pub mod tapi;
pub mod thunks;
pub mod util;
