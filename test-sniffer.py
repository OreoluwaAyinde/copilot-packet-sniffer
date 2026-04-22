from sniffer import mask_ip, redact_text

def test_mask_ip():
    assert mask_ip("192.168.1.25") == "192.168.1.xxx"

def test_email_redaction():
    text = "email=test@gmail.com"
    assert "[REDACTED_EMAIL]" in redact_text(text)

def test_password_redaction():
    text = "password=secret123"
    assert "[REDACTED]" in redact_text(text)