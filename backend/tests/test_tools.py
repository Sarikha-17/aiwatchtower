import pytest

from app.services.tools import ToolError, validate_tool_call


def test_unknown_tool_rejected(runner):
    with pytest.raises(ToolError):
        runner.execute("calendar.delete", {})


def test_extra_fields_rejected():
    with pytest.raises(ToolError):
        validate_tool_call("email.read", {"email_id": "vendor_email_001", "admin": True})


def test_invalid_recipient_rejected():
    with pytest.raises(ToolError):
        validate_tool_call("email.send", {"to": "not-an-address", "subject": "x", "body": "y"})


def test_missing_required_field_rejected():
    with pytest.raises(ToolError):
        validate_tool_call("email.send", {"to": "a@company.example", "body": "y"})


def test_email_read_returns_fake_email(runner):
    out = runner.execute("email.read", {"email_id": "vendor_email_001"})
    assert out["email_id"] == "vendor_email_001"
    assert "INV-1042" in out["subject"]


def test_email_read_unknown_id(runner):
    with pytest.raises(ToolError):
        runner.execute("email.read", {"email_id": "nope"})


def test_hr_file_read_returns_tags(runner):
    out = runner.execute("hr.file.read", {"file_id": "salary_report_q3"})
    assert "hr_sensitive" in out["data_tags"]


def test_email_send_records_in_outbox_only(runner):
    out = runner.execute(
        "email.send",
        {"to": "finance@company.example", "subject": "Hi", "body": "Totals attached",
         "attachment_id": "payroll_summary_approved"},
    )
    assert out["status"] == "sent"
    assert len(runner.outbox) == 1
    assert runner.outbox[0]["to"] == "finance@company.example"


def test_email_send_unknown_attachment(runner):
    with pytest.raises(ToolError):
        runner.execute(
            "email.send",
            {"to": "finance@company.example", "subject": "Hi", "body": "x",
             "attachment_id": "ghost_file"},
        )
    assert runner.outbox == []
