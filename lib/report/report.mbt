///|
pub(all) enum RiskLevel {
  Critical
  High
  Medium
  Low
  Info
} derive(Eq)

///|
pub impl Show for RiskLevel with fn output(self : RiskLevel, logger : &Logger) -> Unit {
  match self {
    Critical => logger.write_string("Critical")
    High => logger.write_string("High")
    Medium => logger.write_string("Medium")
    Low => logger.write_string("Low")
    Info => logger.write_string("Info")
  }
}

///|
pub(all) enum ReportStatus {
  Pass
  Warning
  Fail
} derive(Eq)

///|
pub impl Show for ReportStatus with fn output(
  self : ReportStatus,
  logger : &Logger,
) -> Unit {
  match self {
    Pass => logger.write_string("Pass")
    Warning => logger.write_string("Warning")
    Fail => logger.write_string("Fail")
  }
}

///|
pub(all) struct Finding {
  title : String
  description : String
  risk_level : RiskLevel
  remediation : String
}

///|
pub(all) struct TyposquatSummaryEntry {
  suspect : String
  hit_count : Int
  first_similar_to : String
  first_attack : String
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
  mut risk_score : Double
  mut audit_timestamp : String
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
    risk_score: 0.0,
    audit_timestamp: "2026-01-01T00:00:00Z",
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
  self.risk_score = self.risk_score + risk_level_weight(f.risk_level)
}

///|
/// Recompute `risk_score` and clamp to `[0, 10]`. Call after batch-adding
/// findings so callers don't have to track the running total.
pub fn SecurityReport::recompute_score(self : SecurityReport) -> Unit {
  let mut sum = 0.0
  for i = 0; i < self.findings.length(); i = i + 1 {
    sum = sum + risk_level_weight(self.findings[i].risk_level)
  }
  if sum > 10.0 {
    self.risk_score = 10.0
  } else {
    self.risk_score = sum
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
  s = s + "Risk score: " + format_double(self.risk_score) + " / 10.0\n"
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
  s = s + "\"risk_score\":" + format_double(report.risk_score) + ","
  s = s + "\"audit_timestamp\":\"" + report.audit_timestamp + "\","
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

///|
/// CVSS-style rough weights for each risk level. Critical findings
/// contribute the most to the cumulative risk score; the report
/// clamps the total at 10 so a single Critical + many Lows can't run
/// away.
fn risk_level_weight(level : RiskLevel) -> Double {
  match level {
    Critical => 10.0
    High => 7.0
    Medium => 4.0
    Low => 1.0
    Info => 0.0
  }
}

///|
fn format_double(d : Double) -> String {
  // Render up to 2 decimal places without dragging in locale-sensitive
  // float formatting. Small enough for our `0..10` risk-score range.
  let int_part = d.to_int()
  let frac_part = ((d - int_part.to_double()) * 100.0).to_int()
  if frac_part < 0 {
    return int_part.to_string() + ".00"
  }
  let frac_str = if frac_part < 10 {
    "0" + frac_part.to_string()
  } else {
    frac_part.to_string()
  }
  int_part.to_string() + "." + frac_str
}

///|
/// Convenience constructor that wires a Finding together from common
/// fields. Cuts down on the boilerplate at audit call sites.
pub fn make_finding(
  title : String,
  description : String,
  risk : RiskLevel,
  remediation : String,
) -> Finding {
  { title, description, risk_level: risk, remediation }
}
