from unittest.mock import Mock

from sbom_scorer.data_sources import epss_client


def test_batch_normalizes_deduplicates_and_uses_daily_cache(tmp_path, monkeypatch):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "0.94358",
                "percentile": "0.99996",
                "date": "2026-07-15",
            }
        ]
    }
    get = Mock(return_value=response)
    monkeypatch.setattr(epss_client.requests, "get", get)
    cache_path = tmp_path / "epss.json"

    records = epss_client.get_epss_records_batch(
        [" cve-2021-44228 ", "CVE-2021-44228", "CVE-0000-0000"],
        cache_path=cache_path,
    )
    cached_records = epss_client.get_epss_records_batch(
        ["CVE-2021-44228", "CVE-0000-0000"], cache_path=cache_path
    )

    assert records == cached_records
    assert records["CVE-2021-44228"].percentile == 0.99996
    assert "CVE-0000-0000" not in records
    get.assert_called_once()
    assert get.call_args.kwargs["params"] == {
        "cve": "CVE-2021-44228,CVE-0000-0000"
    }