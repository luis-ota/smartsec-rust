pub mod generator;
pub mod path;
pub mod pdf;

pub use generator::ReportGenerator;
pub use path::{resolve_pdf_path, resolve_report_path};
