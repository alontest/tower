#!/usr/bin/env python3
"""Build the policy-group icon data: the Fluent Emoji 3D index and round flags.

Every exported policy group gets an emoji; its icon is that emoji's Fluent
Emoji 3D image (MIT), referenced from the pinned upstream commit, so nothing
of Fluent is rehosted. Fluent has no country flags: those are flag-icons
(MIT) 1x1 SVGs rendered once into round PNGs and published under
Rulesets/PolicyGroupIcons/, bound to an immutable Tower commit like the
ACL4SSR rule sets (see docs/RELEASING.md).

Quantumult X drew none of the 256px Fluent images on a device, so it gets
its own set: every Fluent emoji on a pale circle of its own hue, 144px like
the icon sets QuanX users use, published next to the flags and read from
raw.githubusercontent.com (no `@` in the URL). The same directory holds the
round flags at 144px for it, named by their emoji the same way.
"""

from __future__ import annotations

import argparse
import base64
import colorsys
import hashlib
import math
import json
import re
import shutil
import subprocess
import tempfile
import zlib
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FLUENT_REPOSITORY = "https://github.com/microsoft/fluentui-emoji.git"
FLUENT_COMMIT = "1ffb34c752ecf5d402f04cfb4b392c77f57c54bc"
FLAG_ICONS_REPOSITORY = "https://github.com/lipis/flag-icons.git"
FLAG_ICONS_COMMIT = "ac7e0eb3259eb62aa6100c435607e2fe03896a97"
CDN = "https://cdn.jsdelivr.net/gh"
TOWER_REPOSITORY = "pengchujin/tower"
FLAG_SIZE = 256
CIRCLE_SIZE = 144
CIRCLE_DIRECTORY = "FluentCircle"
RAW = "https://raw.githubusercontent.com"
# Keeps the files distinct after Xcode flattens resources into the bundle.
RESOURCE_PREFIX = "PolicyGroupIcons_"

ROOT = Path(__file__).resolve().parent.parent
DESTINATION = ROOT / "Tower" / "Resources" / "PolicyGroupIcons"
ARTIFACT_DESTINATION = ROOT / "Rulesets" / "PolicyGroupIcons"
COUNTRY_TABLE = ROOT / "Tower" / "Services" / "CountryTable.swift"


def validated_commit(value: str) -> str:
    normalized = value.lower()
    if len(normalized) != 40 or any(c not in "0123456789abcdef" for c in normalized):
        raise SystemExit(f"不是 40 位提交号：{value}")
    return normalized


def emoji_key(glyph: str) -> str:
    """The lookup key Tower uses: the glyph without variation selectors."""
    return glyph.replace("️", "").replace("︎", "")


def fluent_index(metadata: dict[str, dict], image_paths: list[str]) -> dict[str, str]:
    """Map each emoji to its 3D image, the default skin tone where there are several."""
    by_folder: dict[str, str] = {}
    for path in image_paths:
        parts = path.split("/")
        if len(parts) < 4 or parts[0] != "assets" or not path.endswith(".png"):
            continue
        folder = parts[1]
        if len(parts) == 4 and parts[2] == "3D":
            by_folder.setdefault(folder, path)
        elif len(parts) == 5 and parts[2] == "Default" and parts[3] == "3D":
            by_folder[folder] = path
    index: dict[str, str] = {}
    for folder, entry in sorted(metadata.items()):
        glyph = entry.get("glyph")
        path = by_folder.get(folder)
        if isinstance(glyph, str) and glyph and path:
            index.setdefault(emoji_key(glyph), path)
    return index


def country_codes(country_table: str) -> list[str]:
    return sorted(set(re.findall(r'^\s*"([A-Z]{2})": \.init\(', country_table, re.MULTILINE)))


def file_stem(key: str) -> str:
    """`🚀` → `1f680`; Tower builds the same name from the emoji key."""
    return "-".join(f"{ord(scalar):x}" for scalar in key)


def flag_emoji(code: str) -> str:
    return "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in code.upper())


def png_rgba(data: bytes) -> list[tuple[int, int, int, int]] | None:
    """Pixels of an 8-bit RGBA, non-interlaced PNG (Fluent's 3D images); None otherwise."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    position, header, chunks = 8, None, []
    while position < len(data):
        length = int.from_bytes(data[position:position + 4], "big")
        kind = data[position + 4:position + 8]
        body = data[position + 8:position + 8 + length]
        if kind == b"IHDR":
            header = body
        elif kind == b"IDAT":
            chunks.append(body)
        position += 12 + length
    if header is None or header[8] != 8 or header[9] != 6 or header[12] != 0:
        return None
    width, height = int.from_bytes(header[0:4], "big"), int.from_bytes(header[4:8], "big")
    raw = zlib.decompress(b"".join(chunks))
    stride, previous, pixels = width * 4, bytearray(width * 4), []
    for row in range(height):
        start = row * (stride + 1)
        kind, line = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        for index in range(stride):
            left = line[index - 4] if index >= 4 else 0
            up = previous[index]
            corner = previous[index - 4] if index >= 4 else 0
            if kind == 1:
                line[index] = (line[index] + left) & 0xFF
            elif kind == 2:
                line[index] = (line[index] + up) & 0xFF
            elif kind == 3:
                line[index] = (line[index] + (left + up) // 2) & 0xFF
            elif kind == 4:
                estimate = left + up - corner
                pa, pb, pc = abs(estimate - left), abs(estimate - up), abs(estimate - corner)
                predictor = left if pa <= pb and pa <= pc else up if pb <= pc else corner
                line[index] = (line[index] + predictor) & 0xFF
        pixels.extend(tuple(line[i:i + 4]) for i in range(0, stride, 4))
        previous = line
    return pixels


def pale_background(pixels: list[tuple[int, int, int, int]] | None) -> str:
    """A pale tint of the emoji's own hue, weighted by saturation; grey-blue
    when the emoji has no clear colour."""
    x = y = 0.0
    for red, green, blue, alpha in pixels or []:
        if alpha < 128:
            continue
        hue, lightness, saturation = colorsys.rgb_to_hls(red / 255, green / 255, blue / 255)
        weight = saturation * (1 - abs(lightness - 0.5) * 2)
        x += weight * math.cos(hue * 2 * math.pi)
        y += weight * math.sin(hue * 2 * math.pi)
    if math.hypot(x, y) < 1:
        return "#ECEFF5"
    hue = (math.atan2(y, x) / (2 * math.pi)) % 1
    red, green, blue = colorsys.hls_to_rgb(hue, 0.91, 0.72)
    return "#" + "".join(f"{round(channel * 255):02X}" for channel in (red, green, blue))


def circle_svg(image: bytes, background: str, size: int = CIRCLE_SIZE) -> str:
    """The Fluent image at two thirds of a filled circle."""
    encoded = base64.b64encode(image).decode("ascii")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'width="{size}" height="{size}" viewBox="0 0 144 144">'
        f'<circle cx="72" cy="72" r="72" fill="{background}"/>'
        f'<image x="24" y="24" width="96" height="96" xlink:href="data:image/png;base64,{encoded}"/>'
        "</svg>"
    )


def round_flag_svg(flag_svg: str, size: int = FLAG_SIZE) -> str:
    """A circle of the square flag with a hairline edge, so white and pale
    flags keep their shape on white lists. The flag stays unmodified."""
    body = re.sub(r"<\?xml[^>]*\?>", "", flag_svg).strip()
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 512 512">'
        '<defs><clipPath id="tower-round"><circle cx="256" cy="256" r="232"/></clipPath></defs>'
        f'<g clip-path="url(#tower-round)">{body}</g>'
        '<circle cx="256" cy="256" r="231" fill="none" stroke="#000" stroke-opacity="0.12" stroke-width="4"/>'
        "</svg>"
    )


def run(arguments: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(arguments, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"{' '.join(arguments[:3])} 失败：{(result.stderr or result.stdout).strip()}")
    return result.stdout


def sparse_checkout(repository: str, commit: str, patterns: list[str], into: Path) -> None:
    run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", repository, str(into)])
    run(["git", "sparse-checkout", "set", "--no-cone", *patterns], cwd=into)
    run(["git", "checkout", "-q", commit], cwd=into)


def artifact_base(artifact_commit: str | None) -> str:
    reference = artifact_commit or "main"
    return f"{CDN}/{TOWER_REPOSITORY}@{reference}/Rulesets/PolicyGroupIcons/{FLAG_ICONS_COMMIT}/"


def circle_base(circle_commit: str | None) -> str:
    reference = circle_commit or "main"
    return f"{RAW}/{TOWER_REPOSITORY}/{reference}/Rulesets/PolicyGroupIcons/{CIRCLE_DIRECTORY}/"


def notice_text() -> str:
    return f"""Policy group icons
==================

Emoji images: Microsoft Fluent Emoji, 3D style
Source URL:   https://github.com/microsoft/fluentui-emoji
Revision:     {FLUENT_COMMIT}
License:      MIT

Circles:      the same Fluent 3D images for Quantumult X, each on a pale
              circle of its own hue, rendered to {CIRCLE_SIZE}x{CIRCLE_SIZE} PNG under
              Rulesets/PolicyGroupIcons/{CIRCLE_DIRECTORY}/ (MIT, as Fluent), next
              to the round flags below at the same size (MIT, as flag-icons)

Flags:        flag-icons, 1x1
Source URL:   https://github.com/lipis/flag-icons
Revision:     {FLAG_ICONS_COMMIT}
License:      MIT

PolicyGroupIcons_manifest.json maps each emoji to its Fluent 3D image path at
the revision above; Tower writes the CDN URL of that image into exported
profiles and never bundles or rehosts the images. The round flags are the
flag-icons 1x1 SVGs clipped to a circle with a hairline edge and rendered to
{FLAG_SIZE}x{FLAG_SIZE} PNG; they are published under Rulesets/PolicyGroupIcons/
and remain under the MIT license of flag-icons. Neither is covered by the MIT
license of Tower's own source code; see THIRD-PARTY-NOTICES.md.
Regenerate with: python3 Scripts/update_policy_group_icons.py --rsvg <rsvg-convert>
  --artifact-commit <flags commit> --circle-commit <circles commit>
"""


def build(rsvg: Path, artifact_commit: str | None = None, circle_commit: str | None = None) -> None:
    if artifact_commit is not None:
        artifact_commit = validated_commit(artifact_commit)
    if circle_commit is not None:
        circle_commit = validated_commit(circle_commit)
    work = Path(tempfile.mkdtemp(prefix="tower-icons-"))
    try:
        fluent = work / "fluent"
        sparse_checkout(FLUENT_REPOSITORY, FLUENT_COMMIT, ["/assets/*/metadata.json"], fluent)
        images = run(["git", "ls-tree", "-r", "--name-only", "HEAD", "assets"], cwd=fluent).splitlines()
        metadata = {
            path.parent.name: json.loads(path.read_text(encoding="utf-8"))
            for path in (fluent / "assets").glob("*/metadata.json")
        }
        index = fluent_index(metadata, images)

        # Every emoji: an imported scheme may start a group with any of them.
        wanted = sorted(index)
        run(["git", "sparse-checkout", "add", *(f"/{index[key]}" for key in wanted)], cwd=fluent)
        circles_staging = work / "circles"
        circles_staging.mkdir()
        circles: dict[str, str] = {}
        for key in wanted:
            image = (fluent / index[key]).read_bytes()
            wrapper = work / f"{file_stem(key)}.svg"
            wrapper.write_text(circle_svg(image, pale_background(png_rgba(image))), encoding="utf-8")
            output = circles_staging / f"{file_stem(key)}.png"
            run([str(rsvg), "-w", str(CIRCLE_SIZE), "-h", str(CIRCLE_SIZE), "-o", str(output), str(wrapper)])
            circles[key] = hashlib.sha256(output.read_bytes()).hexdigest()
        (circles_staging / "NOTICE.txt").write_text(notice_text(), encoding="utf-8")

        flags_checkout = work / "flags"
        sparse_checkout(FLAG_ICONS_REPOSITORY, FLAG_ICONS_COMMIT, ["/flags/1x1/*.svg"], flags_checkout)
        staging = work / "artifacts"
        staging.mkdir()
        flags: dict[str, str] = {}
        missing: list[str] = []
        for code in country_codes(COUNTRY_TABLE.read_text(encoding="utf-8")):
            source = flags_checkout / "flags" / "1x1" / f"{code.lower()}.svg"
            if not source.is_file():
                missing.append(code)
                continue
            wrapper = work / f"{code}.svg"
            wrapper.write_text(round_flag_svg(source.read_text(encoding="utf-8")), encoding="utf-8")
            output = staging / f"{code.lower()}.png"
            run([str(rsvg), "-w", str(FLAG_SIZE), "-h", str(FLAG_SIZE), "-o", str(output), str(wrapper)])
            flags[code] = hashlib.sha256(output.read_bytes()).hexdigest()
            small = circles_staging / f"{file_stem(flag_emoji(code))}.png"
            run([str(rsvg), "-w", str(CIRCLE_SIZE), "-h", str(CIRCLE_SIZE), "-o", str(small), str(wrapper)])
            circles[flag_emoji(code)] = hashlib.sha256(small.read_bytes()).hexdigest()
        (staging / "NOTICE.txt").write_text(notice_text(), encoding="utf-8")

        manifest: dict[str, object] = {
            "fluent": {
                "commit": FLUENT_COMMIT,
                "base": f"{CDN}/microsoft/fluentui-emoji@{FLUENT_COMMIT}/",
                "emoji": index,
            },
            "flags": {
                "sourceCommit": FLAG_ICONS_COMMIT,
                "base": artifact_base(artifact_commit),
                "files": flags,
            },
        }
        if artifact_commit is not None:
            manifest["flags"]["artifactCommit"] = artifact_commit
        manifest["circles"] = {"base": circle_base(circle_commit), "files": circles}
        if circle_commit is not None:
            manifest["circles"]["artifactCommit"] = circle_commit

        DESTINATION.mkdir(parents=True, exist_ok=True)
        (DESTINATION / f"{RESOURCE_PREFIX}manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8"
        )
        (DESTINATION / f"{RESOURCE_PREFIX}NOTICE.txt").write_text(notice_text(), encoding="utf-8")
        target = ARTIFACT_DESTINATION / FLAG_ICONS_COMMIT
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(staging, target)
        circles_target = ARTIFACT_DESTINATION / CIRCLE_DIRECTORY
        if circles_target.exists():
            shutil.rmtree(circles_target)
        shutil.copytree(circles_staging, circles_target)
        print(f"完成：{len(index)} 个 Fluent Emoji，{len(flags)} 面国旗 -> {target}，"
              f"{len(circles)} 个 QuanX 圆底图标 -> {circles_target}")
        if missing:
            print(f"flag-icons 没有这些地区，回退为地球图标：{', '.join(missing)}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def fetch(url: str) -> bytes:
    with urlopen(Request(url, headers={"User-Agent": "Tower icon verifier"}), timeout=30) as response:
        return response.read()


def verify_published(fetcher=fetch) -> None:
    manifest = json.loads((DESTINATION / f"{RESOURCE_PREFIX}manifest.json").read_text(encoding="utf-8"))
    flags = manifest["flags"]
    if "artifactCommit" not in flags or "@main/" in flags["base"]:
        raise SystemExit("国旗清单尚未绑定不可变 artifactCommit，不得发布")
    circles = manifest.get("circles", {})
    if "artifactCommit" not in circles or "/main/" in circles.get("base", "/main/"):
        raise SystemExit("QuanX 圆底图标清单尚未绑定不可变 circle commit，不得发布")
    downloads = [(flags["base"] + f"{code.lower()}.png", digest) for code, digest in flags["files"].items()]
    downloads += [(circles["base"] + f"{file_stem(key)}.png", digest) for key, digest in circles["files"].items()]
    for url, digest in sorted(downloads):
        try:
            payload = fetcher(url)
        except (HTTPError, URLError, OSError) as error:
            raise SystemExit(f"图标不可访问：{url}: {error}") from error
        if hashlib.sha256(payload).hexdigest() != digest:
            raise SystemExit(f"图标摘要不一致：{url}")
    print(f"图标已全量验证：{len(flags['files'])} 面国旗，{len(circles['files'])} 个 QuanX 圆底图标")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rsvg", type=Path, help="rsvg-convert 可执行文件路径")
    parser.add_argument("--artifact-commit", help="已推送国旗 PNG 的 Tower 提交号")
    parser.add_argument("--circle-commit", help="已推送 QuanX 圆底图标的 Tower 提交号")
    parser.add_argument("--verify-published", action="store_true", help="回读校验已发布的国旗和圆底图标")
    arguments = parser.parse_args(argv)
    if arguments.verify_published:
        verify_published()
        return
    if arguments.rsvg is None:
        parser.error("生成时必须提供 --rsvg")
    build(arguments.rsvg, arguments.artifact_commit, arguments.circle_commit)


if __name__ == "__main__":
    main()
