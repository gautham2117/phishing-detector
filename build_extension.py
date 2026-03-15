"""
build_extension.py
Generates extension icons and packages the Chrome extension as a ZIP.
Run: python build_extension.py
Output: chrome_extension.zip (load in chrome://extensions)
"""

import os
import zipfile

# ── Generate icons using Pillow ────────────────────────────────────────────────
def generate_icons():
    try:
        from PIL import Image, ImageDraw, ImageFont
        ICONS_DIR = os.path.join("chrome_extension", "icons")
        os.makedirs(ICONS_DIR, exist_ok=True)

        for size in [16, 48, 128]:
            img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)

            # Background circle
            margin = size // 8
            draw.ellipse(
                [margin, margin, size - margin, size - margin],
                fill=(15, 17, 23, 255),
                outline=(56, 139, 253, 255),
                width=max(1, size // 16),
            )

            # Shield symbol
            cx = size // 2
            cy = size // 2
            sh = size // 3

            shield_pts = [
                (cx,        cy - sh),
                (cx + sh,   cy - sh // 2),
                (cx + sh,   cy + sh // 3),
                (cx,        cy + sh),
                (cx - sh,   cy + sh // 3),
                (cx - sh,   cy - sh // 2),
            ]
            draw.polygon(shield_pts, fill=(56, 139, 253, 200))

            img.save(os.path.join(ICONS_DIR, f"icon{size}.png"))
            print(f"  Generated icon{size}.png")

        print("Icons generated successfully.")
        return True

    except ImportError:
        print("Pillow not installed — creating placeholder icons.")
        ICONS_DIR = os.path.join("chrome_extension", "icons")
        os.makedirs(ICONS_DIR, exist_ok=True)

        # Minimal 1x1 transparent PNG (valid but invisible)
        MINIMAL_PNG = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
            b"\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
            b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
            b"\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        for size in [16, 48, 128]:
            path = os.path.join(ICONS_DIR, f"icon{size}.png")
            with open(path, "wb") as f:
                f.write(MINIMAL_PNG)
            print(f"  Placeholder icon{size}.png created")
        return True


# ── Package extension as ZIP ───────────────────────────────────────────────────
def build_zip():
    ext_dir  = "chrome_extension"
    zip_path = "chrome_extension.zip"

    if not os.path.isdir(ext_dir):
        print(f"ERROR: {ext_dir}/ folder not found.")
        return False

    files_to_zip = []
    for root, dirs, files in os.walk(ext_dir):
        # Skip __pycache__ and hidden folders
        dirs[:] = [d for d in dirs if not d.startswith((".", "__"))]
        for fname in files:
            if fname.endswith((".py", ".pyc")):
                continue
            full_path = os.path.join(root, fname)
            arc_path  = os.path.relpath(full_path, ext_dir)
            files_to_zip.append((full_path, arc_path))

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for full_path, arc_path in files_to_zip:
            zf.write(full_path, arc_path)
            print(f"  + {arc_path}")

    print(f"\nExtension packaged → {zip_path}")
    print(f"Total files: {len(files_to_zip)}")
    return True


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== PhishGuard Chrome Extension Builder ===\n")
    print("Step 1: Generating icons…")
    generate_icons()
    print("\nStep 2: Packaging extension ZIP…")
    build_zip()
    print("\nDone!")
    print("\nTo load in Chrome:")
    print("  1. Open chrome://extensions")
    print("  2. Enable 'Developer mode' (top right toggle)")
    print("  3. Click 'Load unpacked'")
    print("  4. Select the chrome_extension/ folder")
    print("     OR drag chrome_extension.zip onto the page")