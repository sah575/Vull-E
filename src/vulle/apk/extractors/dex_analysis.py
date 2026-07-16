from typing import Any


def build_dex_analysis(apk: Any) -> Any:
    from androguard.core.analysis.analysis import Analysis
    from androguard.core.dex import DEX

    analysis = Analysis()
    for dex_bytes in apk.get_all_dex():
        analysis.add(DEX(dex_bytes))
    analysis.create_xref()
    return analysis
