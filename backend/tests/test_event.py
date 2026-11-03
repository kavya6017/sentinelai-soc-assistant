import pytest
from app.schemas.event import NormalizedEvent


def make_event(**overrides):
    data = {
        "timestamp": "2026-10-01T09:00:01Z",
        "source_type": "linux_auth",
        "event_type": "login_failure",
        "src_ip": "203.0.113.50",
        "raw_message": "Failed password for admin from 203.0.113.50",
    }
    data.update(overrides)
    return NormalizedEvent(**data)


def test_bad_ip_is_rejected():
    with pytest.raises(Exception):
        make_event(src_ip="999.1.1.1")


def test_same_input_gives_same_event_id():
    assert make_event().event_id == make_event().event_id