import logging

from app.audit import record_recovery_attempt


def test_successful_attempt_records_account_and_outcome(caplog):
    logger = logging.getLogger("recovery-task")

    with caplog.at_level(logging.INFO, logger=logger.name):
        result = record_recovery_attempt(logger, account_id=42, recovery_token="secret-token", succeeded=True)

    assert result is None
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.INFO
    assert "42" in caplog.records[0].getMessage()
    assert "succeeded" in caplog.records[0].getMessage().lower()


def test_failed_attempt_records_account_and_outcome(caplog):
    logger = logging.getLogger("recovery-task")

    with caplog.at_level(logging.INFO, logger=logger.name):
        record_recovery_attempt(logger, account_id=7, recovery_token="different-secret", succeeded=False)

    assert len(caplog.records) == 1
    assert "7" in caplog.records[0].getMessage()
    assert "failed" in caplog.records[0].getMessage().lower()
