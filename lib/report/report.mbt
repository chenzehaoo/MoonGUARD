///|
/// MoonGuard Report Module
/// Security report generation
pub enum RiskLevel {
  Critical
  High
  Medium
  Low
  Info
}

///|
pub enum ReportStatus {
  Pass
  Warning
  Fail
}

///|
pub struct RiskItem {
  title : String
  description : String
  risk_level : RiskLevel
  remediation : String
}

///|
pub struct SecurityReport {
  package_name : String
  package_version : String
  overall_status : ReportStatus
  total_files : Int
  total_size : Int
}

///|
/// Create a new security report
pub fn SecurityReport::new(
  package_name : String,
  package_version : String,
) -> SecurityReport {
  SecurityReport::{
    package_name,
    package_version,
    overall_status: ReportStatus::Pass,
    total_files: 0,
    total_size: 0,
  }
}

///|
/// Export report to text format
pub fn report_to_text(report : SecurityReport) -> String {
  "MoonGuard Security Report\nPackage: " +
  report.package_name +
  "\nStatus: PASS"
}

///|
/// Export report to HTML format
pub fn report_to_html(report : SecurityReport) -> String {
  "<html><body><h1>MoonGuard Report</h1><p>Package: " +
  report.package_name +
  "</p></body></html>"
}
