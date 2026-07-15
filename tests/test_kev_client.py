from unittest.mock import Mock

from sbom_scorer.data_sources import kev_client


def test_catalog_is_cached_daily_and_preserves_metadata(tmp_path, monkeypatch):
    entry = {
        "cveID": "CVE-2021-44228",
        "dateAdded": "2021-12-10",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
    }
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"vulnerabilities": [entry]}
    get = Mock(return_value=response)
    monkeypatch.setattr(kev_client.requests, "get", get)
    cache_path = tmp_path / "kev.json"

    catalog = kev_client.fetch_kev_catalog(cache_path)
    cached_catalog = kev_client.fetch_kev_catalog(cache_path)

    assert catalog == cached_catalog == [entry]
    assert kev_client.get_kev_map(catalog)["CVE-2021-44228"] == entry
    assert kev_client.is_in_kev(" cve-2021-44228 ", catalog)
    get.assert_called_once_with(kev_client.KEV_FEED_URL, timeout=30)