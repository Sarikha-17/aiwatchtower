from app.services import detectors as d


def test_internal_recipient(cfg):
    assert d.classify_recipient("finance@company.example", cfg) == "internal"


def test_allowlisted_external_recipient(cfg):
    assert d.classify_recipient("billing@acct-vendor.example", cfg) == "allowlisted_external"


def test_unknown_external_recipient(cfg):
    assert d.classify_recipient("external-audit@evil.example", cfg) == "unknown_external"


def test_case_insensitive_domain(cfg):
    assert d.classify_recipient("Finance@COMPANY.example", cfg) == "internal"


def test_lookalike_domains_are_unknown_external(cfg):
    assert d.classify_recipient("x@acct-vendor.example.co", cfg) == "unknown_external"
    assert d.classify_recipient("x@company.example.evil.example", cfg) == "unknown_external"
    assert d.classify_recipient("x@mail.company.example", cfg) == "unknown_external"


def test_attachment_tags_and_sensitivity(store):
    tags = d.attachment_tags("salary_report_q3", store)
    assert d.has_sensitive_hr_tags(tags)
    assert not d.has_sensitive_hr_tags(d.attachment_tags("payroll_summary_approved", store))
    assert d.attachment_tags(None, store) == []
    assert d.attachment_tags("ghost", store) == []


def test_instruction_detection_on_seed_emails(store):
    body = lambda eid: store.emails[eid]["subject"] + " " + store.emails[eid]["body"]
    assert d.detect_instruction_like_text(body("vendor_email_002"))
    assert d.detect_instruction_like_text(body("vendor_email_003"))
    assert not d.detect_instruction_like_text(body("vendor_email_001"))
    assert not d.detect_instruction_like_text(body("vendor_email_004"))
    assert not d.detect_instruction_like_text(body("vendor_email_005"))
