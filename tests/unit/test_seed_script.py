import json
from pathlib import Path

import pytest

from scripts.seed_test_inbox import (
    FIXTURE,
    NOT_LIVE,
    SeedError,
    build_mail,
    check_allowed,
    plan,
    read_allowed,
)


def test_refuses_unlisted_or_identical_accounts() -> None:
    allowed = {"test@example.test", "attacker@example.test"}
    check_allowed("Test@Example.test", "attacker@example.test", allowed)
    with pytest.raises(SeedError, match="target"):
        check_allowed("me@real.test", "attacker@example.test", allowed)
    with pytest.raises(SeedError, match="attacker"):
        check_allowed("test@example.test", "other@example.test", allowed)
    with pytest.raises(SeedError, match="different"):
        check_allowed("test@example.test", "test@example.test", allowed)


def test_missing_allow_list_refuses(tmp_path: Path) -> None:
    with pytest.raises(SeedError, match="no allow-list"):
        read_allowed(tmp_path / "allowed_test_accounts")
    path = tmp_path / "allowed"
    path.write_text("# comment\nA@x.test\n\nb@x.test\n", encoding="utf-8")
    assert read_allowed(path) == {"a@x.test", "b@x.test"}


def test_plan_skips_fixtures_gmail_cannot_send() -> None:
    planned, skipped = plan(json.loads(FIXTURE.read_text(encoding="utf-8")))
    ids = {p.fixture_id for p in planned}
    assert not ids & set(NOT_LIVE)
    assert {"m_forward", "m_hidden", "m_lookalike", "m_replyto", "e_vendor", "e_hidden"} <= ids
    assert "m_spoof" in skipped


def test_mail_uses_display_name_over_attacker_address_and_reply_to() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    by_id = {m["id"]: m for m in fixture["messages"]}
    lookalike = build_mail(by_id["m_lookalike"], "attacker@example.test", "test@example.test")
    assert lookalike["From"] == "Alice <attacker@example.test>"
    replyto = build_mail(by_id["m_replyto"], "attacker@example.test", "test@example.test")
    assert replyto["Reply-To"] == "billing@alice-payments.test"
    hidden = build_mail(by_id["m_hidden"], "attacker@example.test", "test@example.test")
    assert hidden.get_body(preferencelist=("html",)) is not None
