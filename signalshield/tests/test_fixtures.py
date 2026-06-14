from html.parser import HTMLParser
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict[str, str]] = []
        self.forms: list[dict[str, str]] = []
        self.submitters: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            if tag == "form":
                self.forms.append({
                    key: value or ""
                    for key, value in attrs
                })
            elif tag in {"button", "input"}:
                self.submitters.append({
                    key: value or ""
                    for key, value in attrs
                })
            return

        self.links.append({
            key: value or ""
            for key, value in attrs
        })


def test_extension_fixture_has_expected_contract_links() -> None:
    fixture_path = PROJECT_ROOT / "fixtures" / "extension_test_page.html"
    parser = LinkCollector()
    parser.feed(fixture_path.read_text(encoding="utf-8"))

    expected = {
        "safe",
        "dangerous",
        "suspicious",
        "not_found",
        "ignored",
    }
    actual = {
        link.get("data-expected-verdict")
        for link in parser.links
    }

    assert expected <= actual


def test_extension_fixture_contains_ignored_service_link() -> None:
    fixture_path = PROJECT_ROOT / "fixtures" / "extension_test_page.html"
    parser = LinkCollector()
    parser.feed(fixture_path.read_text(encoding="utf-8"))

    ignored_links = [
        link
        for link in parser.links
        if link.get("data-expected-verdict") == "ignored"
    ]

    assert ignored_links
    assert all(link.get("data-ss-ignore") == "1" for link in ignored_links)


def test_extension_fixture_contains_risky_form_action() -> None:
    fixture_path = PROJECT_ROOT / "fixtures" / "extension_test_page.html"
    parser = LinkCollector()
    parser.feed(fixture_path.read_text(encoding="utf-8"))

    assert any(
        form.get("action") == "https://mbank-login24.pl/collect"
        for form in parser.forms
    )


def test_extension_fixture_contains_risky_submitter_formaction() -> None:
    fixture_path = PROJECT_ROOT / "fixtures" / "extension_test_page.html"
    parser = LinkCollector()
    parser.feed(fixture_path.read_text(encoding="utf-8"))

    assert any(
        submitter.get("formaction") == "https://mbank-login24.pl/button-collect"
        for submitter in parser.submitters
    )
