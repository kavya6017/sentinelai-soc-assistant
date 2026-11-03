from app.services.ingestion.linux_auth import parse_lines

FAILED = "Oct  1 09:00:01 web-01 sshd[812]: Failed password for admin from 203.0.113.50 port 5522 ssh2"
ACCEPTED = "Oct  1 09:00:13 web-01 sshd[814]: Accepted password for admin from 203.0.113.50 port 5530 ssh2"
INVALID_USER = "Oct  1 09:00:05 web-01 sshd[813]: Failed password for invalid user test from 203.0.113.50 port 5526 ssh2"
CRON = "Oct  1 09:05:00 web-01 CRON[901]: pam_unix(cron:session): session opened for user root"
BROKEN = "this line is broken and has no useful structure"


def test_failed_login_is_parsed_correctly():
    result = parse_lines([FAILED], year=2026)
    assert len(result.events) == 1
    e = result.events[0]
    assert e.event_type == "login_failure"
    assert e.status.value == "failure"
    assert e.username == "admin"
    assert e.src_ip == "203.0.113.50"
    assert e.hostname == "web-01"
    assert e.timestamp.isoformat() == "2026-10-01T09:00:01+00:00"
    assert e.raw_message == FAILED


def test_accepted_login_is_success():
    e = parse_lines([ACCEPTED], year=2026).events[0]
    assert e.event_type == "login_success"
    assert e.status.value == "success"


def test_invalid_user_flag_is_set():
    e = parse_lines([INVALID_USER], year=2026).events[0]
    assert e.username == "test"
    assert e.metadata["invalid_user"] is True


def test_unrelated_syslog_line_is_skipped_not_error():
    result = parse_lines([CRON], year=2026)
    assert result.events == []
    assert result.skipped == 1
    assert result.errors == []


def test_broken_line_is_reported_with_line_number():
    result = parse_lines([FAILED, BROKEN], year=2026)
    assert len(result.events) == 1          # the good line still parsed
    assert len(result.errors) == 1
    assert result.errors[0].line_number == 2


def test_bom_at_start_of_file_is_handled():
    result = parse_lines(["\ufeff" + FAILED], year=2026)
    assert len(result.events) == 1
    assert result.errors == []


# --- YOUR TURN: write these two ---

def test_blank_lines_are_ignored():
    # TODO: pass ["", "   ", FAILED] and check you get 1 event, 0 errors
    pass


def test_year_parameter_is_used():
    # TODO: parse FAILED with year=2025 and check the event's timestamp.year is 2025
    pass