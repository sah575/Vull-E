import io
import zipfile
from typing import Any

from vulle.apk.limits import MAX_NATIVE_LIBRARIES_ANALYZED
from vulle.apk.models import NativeLibraryInfo

_PREFERRED_ABI_ORDER = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
_DF_BIND_NOW = 0x00000008
_DF_1_NOW = 0x00000001
_JNI_SYMBOL_PREFIX = "Java_"
_STACK_CHK_FAIL_SYMBOL = "__stack_chk_fail"
_UNDEFINED_SECTION_INDEX = "SHN_UNDEF"


def analyze_native_libraries(
    archive: zipfile.ZipFile,
    native_libraries: list[NativeLibraryInfo],
) -> list[NativeLibraryInfo]:
    if not native_libraries:
        return native_libraries

    selected_abi = _select_abi(native_libraries)
    analyzed: list[NativeLibraryInfo] = []
    analyzed_count = 0
    for library in native_libraries:
        if library.abi != selected_abi or analyzed_count >= MAX_NATIVE_LIBRARIES_ANALYZED:
            analyzed.append(library)
            continue
        analyzed.append(_analyze_one(archive, library))
        analyzed_count += 1
    return analyzed


def _select_abi(native_libraries: list[NativeLibraryInfo]) -> str:
    available = {library.abi for library in native_libraries}
    for abi in _PREFERRED_ABI_ORDER:
        if abi in available:
            return abi
    return sorted(available)[0]


def _analyze_one(archive: zipfile.ZipFile, library: NativeLibraryInfo) -> NativeLibraryInfo:
    try:
        raw = archive.read(library.path)
        facts = _parse_elf(raw)
        return library.model_copy(update=facts)
    except Exception as exc:
        return library.model_copy(
            update={"parse_error": f"{exc.__class__.__name__}: {exc}"}
        )


def _parse_elf(raw: bytes) -> dict[str, Any]:
    from elftools.elf.constants import P_FLAGS
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    elf = ELFFile(io.BytesIO(raw))

    nx_enabled: bool | None = None
    relro: str = "none"
    for index in range(elf.num_segments()):
        segment = elf.get_segment(index)
        if segment["p_type"] == "PT_GNU_STACK":
            nx_enabled = not bool(segment["p_flags"] & P_FLAGS.PF_X)
        elif segment["p_type"] == "PT_GNU_RELRO":
            relro = "partial"

    if relro == "partial":
        dynamic = elf.get_section_by_name(".dynamic")
        if isinstance(dynamic, DynamicSection):
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & _DF_BIND_NOW:
                    relro = "full"
                if tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & _DF_1_NOW:
                    relro = "full"

    stack_canary_detected = False
    exported_jni_symbols = []
    dynsym = elf.get_section_by_name(".dynsym")
    if isinstance(dynsym, SymbolTableSection):
        for symbol in dynsym.iter_symbols():
            if not symbol.name:
                continue
            is_undefined = symbol["st_shndx"] == _UNDEFINED_SECTION_INDEX
            if symbol.name == _STACK_CHK_FAIL_SYMBOL and is_undefined:
                stack_canary_detected = True
            if symbol.name.startswith(_JNI_SYMBOL_PREFIX) and not is_undefined:
                exported_jni_symbols.append(symbol.name)

    return {
        "nx_enabled": nx_enabled,
        "relro": relro,
        "stack_canary_detected": stack_canary_detected,
        "exported_jni_symbols": exported_jni_symbols,
        "parse_error": None,
    }
