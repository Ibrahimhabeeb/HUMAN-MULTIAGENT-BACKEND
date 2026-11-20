import logging

import pytest
from app.audit import record_recovery_attempt


@pytest.mark.parametrize("succeeded", [True, False])
@pytest.mark.parametrize("token", [
    "SECRETBEGIN-928fe0bb71e745d3-SECRETEND",
    "UNICODEBEGIN-Caf\u00e9-928fe0bb71e7-UNICODEEND",
    "LINEBEGIN-928fe0bb\n71e745d3-LINEEND",
])
def test_recovery_audit_keeps_secrets_out_of_all_log_fields(caplog, succeeded, token):
    logger = logging.getLogger("hidden-recovery-assessment")
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        result = record_recovery_attempt(logger, 731, token, succeeded)
    assert result is None
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == logging.INFO
    assert "731" in record.getMessage()
    assert ("succeeded" if succeeded else "failed") in record.getMessage().lower()
    rendered = record.getMessage() + repr(record.__dict__)
    for secret in (token, token[:8], token[-8:]):
        assert secret not in rendered
