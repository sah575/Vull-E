from pathlib import Path

from typer.testing import CliRunner

from vulle.cli import app
from vulle.rag.importers import (
    import_mitre_capec,
    import_mitre_cwe,
    import_owasp_mastg,
    import_owasp_masvs,
    import_owasp_wstg,
    import_payloads,
)

FIXTURES = Path("tests/fixtures/importers")


def test_import_owasp_wstg_normalizes_selected_markdown(tmp_path: Path) -> None:
    report = import_owasp_wstg(FIXTURES / "owasp-wstg", tmp_path)
    generated = sorted((tmp_path / "owasp-wstg").rglob("*.md"))

    assert report.files_written == 2
    assert generated
    text = generated[0].read_text(encoding="utf-8")
    assert "Source: OWASP WSTG" in text
    assert "Imported Content" in text


def test_import_owasp_masvs_normalizes_mobile_standard(tmp_path: Path) -> None:
    report = import_owasp_masvs(FIXTURES / "owasp-masvs", tmp_path)
    generated = sorted((tmp_path / "owasp-masvs").rglob("*.md"))
    combined = "\n".join(path.read_text(encoding="utf-8") for path in generated)

    assert report.files_written == 2
    assert "Source: OWASP MASVS" in combined
    assert "MASVS-NETWORK" in combined
    assert "certificate validation" in combined


def test_import_owasp_mastg_selects_mobile_testing_guidance(tmp_path: Path) -> None:
    report = import_owasp_mastg(FIXTURES / "owasp-mastg", tmp_path)
    generated_paths = {path.as_posix() for path in (tmp_path / "owasp-mastg").rglob("*.md")}
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in (tmp_path / "owasp-mastg").rglob("*.md")
    )

    assert report.files_written == 2
    assert "Source: OWASP MASTG" in combined
    assert "Testing Certificate Pinning" in combined
    assert "Android Data Storage" in combined
    assert not any("demo" in path for path in generated_paths)


def test_import_payloads_filters_to_appsec_api_topics(tmp_path: Path) -> None:
    report = import_payloads(FIXTURES / "payloads", tmp_path)
    generated_paths = {path.as_posix() for path in (tmp_path / "payloads").rglob("*.md")}

    assert report.files_written == 2
    assert any("sql-injection" in path for path in generated_paths)
    assert any("server-side-request-forgery" in path for path in generated_paths)
    assert not any("windows-privilege-escalation" in path for path in generated_paths)


def test_import_mitre_cwe_converts_relevant_csv_records(tmp_path: Path) -> None:
    report = import_mitre_cwe(FIXTURES / "mitre" / "cwe.csv", tmp_path)
    generated = sorted((tmp_path / "mitre-cwe").rglob("*.md"))
    combined = "\n".join(path.read_text(encoding="utf-8") for path in generated)

    assert report.records_scanned == 3
    assert report.records_written == 2
    assert "MITRE CWE - 89: SQL Injection" in combined
    assert "MITRE CWE - 862: Missing Authorization" in combined
    assert "Unrelated Hardware Issue" not in combined


def test_import_mitre_capec_converts_relevant_xml_records(tmp_path: Path) -> None:
    report = import_mitre_capec(FIXTURES / "mitre" / "capec.xml", tmp_path)
    generated = sorted((tmp_path / "mitre-capec").rglob("*.md"))
    combined = "\n".join(path.read_text(encoding="utf-8") for path in generated)

    assert report.records_scanned == 2
    assert report.records_written == 1
    assert "MITRE CAPEC - 115: Authentication Bypass" in combined
    assert "Physical Tampering" not in combined


def test_cli_import_command_writes_report_and_files(tmp_path: Path) -> None:
    runner = CliRunner()
    output_root = tmp_path / "generated"
    result = runner.invoke(
        app,
        [
            "rag-import-payloads",
            str(FIXTURES / "payloads"),
            "--output-root",
            str(output_root),
        ],
    )

    assert result.exit_code == 0
    assert "Files written: 2" in result.output
    assert list((output_root / "payloads").rglob("*.md"))
