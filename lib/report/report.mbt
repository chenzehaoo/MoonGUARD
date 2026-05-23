///|
pub(all) enum RiskLevel {
  Critical
  High
  Medium
  Low
  Info
} derive(Eq, Show)

///|
pub(all) enum ReportStatus {
  Pass
  Warning
  Fail
} derive(Eq, Show)

///|
pub(all) struct Finding {
  title : String
  description : String
  risk_level : RiskLevel
  remediation : String
}

///|
pub(all) struct SecurityReport {
  package_name : String
  package_version : String
  mut overall_status : ReportStatus
  mut findings : Array[Finding]
  mut signature_verified : Bool
  mut typosquat_suspects : Array[String]
  mut file_count : Int
}

///|
pub fn SecurityReport::new(
  package_name : String,
  package_version : String,
) -> SecurityReport {
  SecurityReport::{
    package_name,
    package_version,
    overall_status: Pass,
    findings: [],
    signature_verified: false,
    typosquat_suspects: [],
    file_count: 0,
  }
}

///|
pub fn SecurityReport::add_finding(self : SecurityReport, f : Finding) -> Unit {
  self.findings.push(f)
  match f.risk_level {
    Critical | High => self.overall_status = Fail
    Medium => if self.overall_status == Pass { self.overall_status = Warning }
    _ => ()
  }
}

///|
pub fn SecurityReport::summary(self : SecurityReport) -> String {
  let status_str = match self.overall_status {
    Pass => "PASS"
    Warning => "WARNING"
    Fail => "FAIL"
  }
  let mut critical = 0
  let mut high = 0
  let mut medium = 0
  let mut low = 0
  for i = 0; i < self.findings.length(); i = i + 1 {
    match self.findings[i].risk_level {
      Critical => critical = critical + 1
      High => high = high + 1
      Medium => medium = medium + 1
      Low => low = low + 1
      Info => ()
    }
  }
  let mut s = "MoonGuard Security Report\n"
  s = s + "========================\n"
  s = s + "Package: " + self.package_name + " v" + self.package_version + "\n"
  s = s + "Status: " + status_str + "\n"
  s = s + "Signature: "
  s = s + (if self.signature_verified { "verified" } else { "unverified" })
  s = s + "\n"
  s = s + "Files: " + self.file_count.to_string() + "\n"
  s = s + "Findings: " + self.findings.length().to_string() + " total"
  if critical > 0 {
    s = s + " (" + critical.to_string() + " critical)"
  }
  if high > 0 {
    s = s + " (" + high.to_string() + " high)"
  }
  if medium > 0 {
    s = s + " (" + medium.to_string() + " medium)"
  }
  if low > 0 {
    s = s + " (" + low.to_string() + " low)"
  }
  s = s + "\n"
  if self.typosquat_suspects.length() > 0 {
    s = s + "Typosquat alerts: "
    s = s + self.typosquat_suspects.length().to_string() + "\n"
  }
  s
}

///|
pub fn report_to_json(report : SecurityReport) -> String {
  let status_str = match report.overall_status {
    Pass => "pass"
    Warning => "warning"
    Fail => "fail"
  }
  let mut s = "{\"package\":\"" + report.package_name + "\","
  s = s + "\"version\":\"" + report.package_version + "\","
  s = s + "\"status\":\"" + status_str + "\","
  s = s +
    "\"signature_verified\":" +
    report.signature_verified.to_string() +
    ","
  s = s + "\"file_count\":" + report.file_count.to_string() + ","
  s = s + "\"findings\":["
  for i = 0; i < report.findings.length(); i = i + 1 {
    if i > 0 {
      s = s + ","
    }
    let f = report.findings[i]
    s = s + "{\"title\":\"" + f.title + "\","
    s = s + "\"risk\":\"" + risk_level_str(f.risk_level) + "\","
    s = s + "\"description\":\"" + f.description + "\","
    s = s + "\"remediation\":\"" + f.remediation + "\"}"
  }
  s = s + "],"
  s = s + "\"typosquat_suspects\":["
  for i = 0; i < report.typosquat_suspects.length(); i = i + 1 {
    if i > 0 {
      s = s + ","
    }
    s = s + "\"" + report.typosquat_suspects[i] + "\""
  }
  s = s + "]}"
  s
}

///|
fn risk_level_str(level : RiskLevel) -> String {
  match level {
    Critical => "critical"
    High => "high"
    Medium => "medium"
    Low => "low"
    Info => "info"
  }
}
