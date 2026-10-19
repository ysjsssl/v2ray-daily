"""Install a pinned official Linux amd64 Xray binary with SHA256 verification."""

import hashlib
import io
from pathlib import Path
from urllib.request import Request, urlopen
import zipfile


VERSION = "v26.3.27"
SHA256 = "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
URL = f"https://github.com/XTLS/Xray-core/releases/download/{VERSION}/Xray-linux-64.zip"


def main():
    with urlopen(Request(URL, headers={"User-Agent": "v2ray-daily/1.0"}), timeout=120) as response:
        archive = response.read(80 * 1024 * 1024 + 1)
    if hashlib.sha256(archive).hexdigest() != SHA256:
        raise ValueError("Official Xray archive SHA256 mismatch")
    destination = Path("bin/xray")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        destination.write_bytes(bundle.read("xray"))
    destination.chmod(0o755)
    print(f"Installed verified Xray {VERSION}")


if __name__ == "__main__":
    main()
