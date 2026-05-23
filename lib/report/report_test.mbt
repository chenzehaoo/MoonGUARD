///|
test "report basic flow" {
  let r = @report.SecurityReport::new("my-pkg", "1.0.0")
  r.add_finding(@report.Finding::{
    title: "unsigned package",
    description: "no signature found",
    risk_level: @report.RiskLevel::High,
    remediation: "sign the package",
  })
  r.add_finding(@report.Finding::{
    title: "typosquat suspect",
    description: "similar to known package",
    risk_level: @report.RiskLevel::Medium,
    remediation: "verify package name",
  })
  r.typosquat_suspects.push("my_pkg")
  r.file_count = 10
  inspect(r.overall_status, content="Fail")
  let summary = r.summary()
  inspect(summary.contains("FAIL"), content="true")
  inspect(summary.contains("my-pkg"), content="true")
  let json = @report.report_to_json(r)
  inspect(json.contains("\"status\":\"fail\""), content="true")
  inspect(json.contains("unsigned package"), content="true")
}
