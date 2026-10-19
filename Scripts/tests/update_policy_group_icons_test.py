#!/usr/bin/env python3

import importlib.util
import json
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "update_policy_group_icons.py"
SPEC = importlib.util.spec_from_file_location("update_policy_group_icons", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
icons = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(icons)


class UpdatePolicyGroupIconsTests(unittest.TestCase):
    def test_index_maps_glyphs_to_3d_images_preferring_the_default_skin_tone(self) -> None:
        metadata = {
            "Rocket": {"glyph": "🚀"},
            "Recycling symbol": {"glyph": "♻️"},
            "Thumbs up": {"glyph": "👍"},
            "No image": {"glyph": "🫥"},
        }
        paths = [
            "assets/Rocket/3D/rocket_3d.png",
            "assets/Rocket/Flat/rocket_flat.svg",
            "assets/Recycling symbol/3D/recycling_symbol_3d.png",
            "assets/Thumbs up/Dark/3D/thumbs_up_3d_dark.png",
            "assets/Thumbs up/Default/3D/thumbs_up_3d_default.png",
        ]
        index = icons.fluent_index(metadata, paths)
        self.assertEqual(index["🚀"], "assets/Rocket/3D/rocket_3d.png")
        # Keys drop the variation selector, as Tower does when it looks one up.
        self.assertEqual(index["♻"], "assets/Recycling symbol/3D/recycling_symbol_3d.png")
        self.assertEqual(index["👍"], "assets/Thumbs up/Default/3D/thumbs_up_3d_default.png")
        self.assertNotIn("🫥", index)

    def test_country_codes_come_from_the_generated_table(self) -> None:
        table = '''
            "HK": .init(chineseName: "香港", englishName: "Hong Kong", latitude: 0, longitude: 0, names: [], codes: []),
            "JP": .init(chineseName: "日本", englishName: "Japan", latitude: 0, longitude: 0, names: [], codes: []),
            // "XX": .init(
        '''
        self.assertEqual(icons.country_codes(table), ["HK", "JP"])

    def test_round_flag_keeps_the_flag_and_adds_only_a_clip_and_a_hairline(self) -> None:
        flag = '<?xml version="1.0"?><svg viewBox="0 0 512 512"><path fill="#EC1B2E" d="M0 0h512v512H0"/></svg>'
        wrapper = icons.round_flag_svg(flag, size=128)
        self.assertIn('width="128" height="128"', wrapper)
        self.assertIn('<path fill="#EC1B2E" d="M0 0h512v512H0"/>', wrapper)
        self.assertNotIn("<?xml", wrapper)
        self.assertIn('clip-path="url(#tower-round)"', wrapper)

    def test_unpublished_flags_point_at_main_and_are_marked_so(self) -> None:
        self.assertIn("@main/", icons.artifact_base(None))
        commit = "a" * 40
        self.assertIn(f"@{commit}/Rulesets/PolicyGroupIcons/{icons.FLAG_ICONS_COMMIT}/", icons.artifact_base(commit))
        with self.assertRaises(SystemExit):
            icons.validated_commit("main")

    def test_circle_files_are_named_by_scalars(self) -> None:
        self.assertEqual(icons.file_stem("🚀"), "1f680")
        self.assertEqual(icons.file_stem("♻"), "267b")
        self.assertEqual(icons.file_stem(icons.flag_emoji("HK")), "1f1ed-1f1f0")

    def test_circle_background_is_a_pale_tint_of_the_emoji(self) -> None:
        red = [(220, 30, 30, 255)] * 10
        background = icons.pale_background(red)
        r, g, b = (int(background[i:i + 2], 16) for i in (1, 3, 5))
        self.assertGreater(r, g)
        self.assertGreater(min(r, g, b), 200, background)
        self.assertEqual(icons.pale_background([(128, 128, 128, 255)] * 10), "#ECEFF5")
        self.assertEqual(icons.pale_background(None), "#ECEFF5")

    def test_png_decoder_reads_every_filter(self) -> None:
        import struct
        import zlib
        rows = [(0, [1, 2, 3, 255, 4, 5, 6, 255]), (1, [1, 2, 3, 255, 4, 5, 6, 255]),
                (2, [1, 1, 1, 0, 1, 1, 1, 0]), (3, [9, 9, 9, 255, 1, 1, 1, 0]), (4, [0, 0, 0, 0, 0, 0, 0, 0])]
        raw = b"".join(bytes([kind, *values]) for kind, values in rows)
        def chunk(kind: bytes, body: bytes) -> bytes:
            return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
        png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 5, 8, 6, 0, 0, 0))
               + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
        pixels = icons.png_rgba(png)
        self.assertEqual(pixels[0], (1, 2, 3, 255))
        self.assertEqual(pixels[3], (5, 7, 9, 254))  # Sub: adds the pixel to the left
        self.assertEqual(pixels[4], (2, 3, 4, 255))  # Up: adds the pixel above
        self.assertEqual(len(pixels), 10)
        self.assertIsNone(icons.png_rgba(b"not a png"))

    def test_checked_in_manifest_matches_the_published_flags(self) -> None:
        manifest = json.loads((icons.DESTINATION / f"{icons.RESOURCE_PREFIX}manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["fluent"]["commit"], icons.FLUENT_COMMIT)
        self.assertGreater(len(manifest["fluent"]["emoji"]), 1500)
        directory = icons.ARTIFACT_DESTINATION / icons.FLAG_ICONS_COMMIT
        files = manifest["flags"]["files"]
        self.assertEqual({path.stem.upper() for path in directory.glob("*.png")}, set(files))
        import hashlib
        for code, digest in files.items():
            self.assertEqual(hashlib.sha256((directory / f"{code.lower()}.png").read_bytes()).hexdigest(), digest, code)
        circles = manifest["circles"]["files"]
        circle_directory = icons.ARTIFACT_DESTINATION / icons.CIRCLE_DIRECTORY
        self.assertEqual({path.stem for path in circle_directory.glob("*.png")}, {icons.file_stem(key) for key in circles})
        flags_as_emoji = {icons.flag_emoji(code) for code in files}
        self.assertEqual(set(circles) - flags_as_emoji, set(manifest["fluent"]["emoji"]), "every Fluent emoji")
        self.assertTrue(flags_as_emoji <= set(circles), "every flag also at 144px")
        for key, digest in circles.items():
            path = circle_directory / f"{icons.file_stem(key)}.png"
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest, key)


if __name__ == "__main__":
    unittest.main()
