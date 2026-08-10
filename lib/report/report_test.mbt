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
  inspect(json.contains("\"risk_score\":"), content="true")
}

///|
test "report medium-only finding is a warning, not a failure" {
  let r = @report.SecurityReport::new("pkg", "0.1.0")
  r.add_finding(@report.Finding::{
    title: "minor",
    description: "minor issue",
    risk_level: @report.RiskLevel::Medium,
    remediation: "review later",
  })
  inspect(r.overall_status, content="Warning")
}

///|
test "report recompute_score clamps at 10" {
  let r = @report.SecurityReport::new("pkg", "0.1.0")
  r.add_finding(@report.Finding::{
    title: "x",
    description: "x",
    risk_level: @report.RiskLevel::Critical,
    remediation: "x",
  })
  r.add_finding(@report.Finding::{
    title: "y",
    description: "y",
    risk_level: @report.RiskLevel::Critical,
    remediation: "y",
  })
  r.recompute_score()
  inspect(r.risk_score == 10.0, content="true")
}

///|
test "report recompute_score sums up partial findings" {
  let r = @report.SecurityReport::new("pkg", "0.1.0")
  r.add_finding(@report.Finding::{
    title: "a",
    description: "a",
    risk_level: @report.RiskLevel::Low,
    remediation: "a",
  })
  r.add_finding(@report.Finding::{
    title: "b",
    description: "b",
    risk_level: @report.RiskLevel::Low,
    remediation: "b",
  })
  r.recompute_score()
  // 2 * 1.0 = 2.0
  inspect(r.risk_score == 2.0, content="true")
}

///|
test "make_finding constructs struct cleanly" {
  let f = @report.make_finding(
    "test",
    "desc",
    @report.RiskLevel::High,
    "fix it",
  )
  inspect(f.title, content="test")
  inspect(f.risk_level == @report.RiskLevel::High, content="true")
}

///|
test "report json contains risk_score and timestamp" {
  let r = @report.SecurityReport::new("pkg", "1.0.0")
  r.add_finding(@report.Finding::{
    title: "x",
    description: "x",
    risk_level: @report.RiskLevel::High,
    remediation: "x",
  })
  r.recompute_score()
  let json = @report.report_to_json(r)
  inspect(json.contains("\"audit_timestamp\":"), content="true")
  inspect(json.contains("\"risk_score\":7.00"), content="true")
}

///|
test "report json escapes quotes and backslashes" {
  let r = @report.SecurityReport::new("pkg\"evil", "1.0.0")
  r.add_finding(@report.Finding::{
    title: "say \"hi\" \\ path",
    description: "line1\nline2",
    risk_level: @report.RiskLevel::High,
    remediation: "tab\there",
  })
  r.typosquat_suspects.push("bad\"name")
  let json = @report.report_to_json(r)
  // Raw quotes inside the JSON body must be escaped, not structural.
  inspect(json.contains("\\\""), content="true")
  inspect(json.contains("\\\\"), content="true")
  inspect(json.contains("\\n"), content="true")
  inspect(json.contains("\\t"), content="true")
  inspect(json.contains("\"package\":\"pkg\\\"evil\""), content="true")
  // No unescaped raw newline may appear inside a string value.
  inspect(json.contains("line1\nline2"), content="false")
}
