from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable

from pydantic import BaseModel, Field

from app.schemas.event import EventStatus, NormalizedEvent

SOURCE_TYPE = "linux_auth"

# Matches: "Oct  1 09:00:01 web-01 sshd[812]: <message>"
SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

# Matches the message part of SSH login attempts.
SSH_RE = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>\w+) for "
    r"(?:(?P<invalid>invalid user) )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)


class ParseError(BaseModel):
    line_number: int
    reason: str
    line: str


class ParseResult(BaseModel):
    events: list[NormalizedEvent] = Field(default_factory=list)
    errors: list[ParseError] = Field(default_factory=list)
    skipped: int = 0


def parse_line(line: str, year: int) -> NormalizedEvent | None:
    """Return an event; None if the line is valid syslog but not an SSH login;
    raise ValueError if the line cannot be parsed."""
    m = SYSLOG_RE.match(line)
    if not m:
        raise ValueError("not a syslog-formatted line")

    ssh = SSH_RE.match(m["msg"])
    if not ssh:
        return None  # valid line, just not something we detect on

    ts = datetime.strptime(
        f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=timezone.utc)  # syslog has no time zone; we assume UTC

    failed = ssh["result"] == "Failed"
    return NormalizedEvent(
        timestamp=ts,
        source_type=SOURCE_TYPE,
        event_type="login_failure" if failed else "login_success",
        src_ip=ssh["ip"],
        username=ssh["user"],
        hostname=m["host"],
        process=m["proc"],
        action="authentication",
        status=EventStatus.FAILURE if failed else EventStatus.SUCCESS,
        raw_message=line,
        metadata={
            "port": int(ssh["port"]),
            "auth_method": ssh["method"],
            "invalid_user": ssh["invalid"] is not None,
            "pid": int(m["pid"]) if m["pid"] else None,
        },
    )


def parse_lines(lines: Iterable[str], year: int | None = None) -> ParseResult:
    year = year or datetime.now(timezone.utc).year
    result = ParseResult()

    for number, raw in enumerate(lines, start=1):
        line = raw.lstrip("\ufeff").rstrip("\r\n")
        if not line.strip():
            continue
        try:
            event = parse_line(line, year)
        except ValueError as exc:  # also catches pydantic ValidationError
            result.errors.append(
                ParseError(line_number=number, reason=str(exc)[:200], line=line[:200])
            )
            continue

        if event is None:
            result.skipped += 1
        else:
            result.events.append(event)

    return result