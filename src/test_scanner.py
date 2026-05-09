from src.scanner import scan_content

def test_detect_aws_key():
    sample = "AKIA1234567890ABCDE"
    assert "AWS_KEY" in scan_content(sample)