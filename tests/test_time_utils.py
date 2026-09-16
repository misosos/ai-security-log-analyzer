from datetime import datetime, timezone, timedelta

import pytest

from app.parser.time_utils import normalize_to_utc


def test_normalize_to_utc():

    timestamp = datetime(
        2026,
        9,
        14,
        11,
        0,
        1,
        tzinfo=timezone(timedelta(hours=9)),
    )

    result = normalize_to_utc(timestamp)

    assert result == datetime(
        2026,
        9,
        14,
        2,
        0,
        1,
        tzinfo=timezone.utc,
    )


def test_normalize_to_utc_rejects_naive_datetime():

    timestamp = datetime(
        2026,
        9,
        14,
        11,
        0,
        1,
    )

    with pytest.raises(ValueError):
        normalize_to_utc(timestamp)