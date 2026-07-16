import zipfile

from vulle.apk.models import NativeLibraryInfo

_NATIVE_LIB_PREFIX = "lib/"


def extract_dex_files(archive: zipfile.ZipFile) -> list[str]:
    return sorted(
        name for name in archive.namelist() if name == "classes.dex" or _is_multidex(name)
    )


def _is_multidex(name: str) -> bool:
    if not name.startswith("classes") or not name.endswith(".dex"):
        return False
    return name[len("classes") : -len(".dex")].isdigit()


def extract_native_libraries(archive: zipfile.ZipFile) -> list[NativeLibraryInfo]:
    libraries = []
    for name in sorted(archive.namelist()):
        if not name.startswith(_NATIVE_LIB_PREFIX) or not name.endswith(".so"):
            continue
        parts = name.split("/")
        if len(parts) < 3:
            continue
        abi = parts[1]
        libraries.append(NativeLibraryInfo(path=name, abi=abi))
    return libraries
