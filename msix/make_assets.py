"""Tile, taskbar and Store logos for the MSIX package, from MeowSecurity.Gui/meow-security.png.

The artwork is a cat on an orange disc with a transparent surround. That reads well large and
turns to mush at taskbar sizes, so the small icons are composed on an opaque brand disc and
sharpened, and the wide tile sits the art on a brand gradient instead of stretching it.
"""
import os
import sys

from PIL import Image, ImageDraw, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SOURCE = os.path.join(ROOT, "MeowSecurity.Gui", "meow-security.png")

# The product's orange, and a dark bed for the wide tile.
BRAND = (255, 154, 56)
DARK_TOP, DARK_BOTTOM = (24, 32, 46), (12, 17, 26)

ART = Image.open(SOURCE).convert("RGBA")


def gradient(w, h, top=DARK_TOP, bottom=DARK_BOTTOM):
    img = Image.new("RGBA", (w, h))
    d = ImageDraw.Draw(img)
    for y in range(h):
        t = y / max(1, h - 1)
        d.line([(0, y), (w, y)],
               fill=tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)) + (255,))
    return img


def art(size):
    """The artwork alone, on transparency. Used where the shell provides its own backdrop."""
    return ART.resize((size, size), Image.LANCZOS)


def small(size):
    """
    Taskbar and list sizes.

    Rendered four times larger and reduced, so the cat's outline survives; below 32 pixels it
    also gets an unsharp pass, because a soft icon at 16 pixels reads as a smudge.
    """
    ss = 4
    S = size * ss
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    a = ART.resize((S, S), Image.LANCZOS)
    img.alpha_composite(a)

    out = img.resize((size, size), Image.LANCZOS)
    if size <= 32:
        out = out.filter(ImageFilter.UnsharpMask(radius=0.6, percent=70, threshold=0))
    return out


def wide(w, h):
    img = gradient(w, h)
    a = art(int(h * 0.82))
    img.alpha_composite(a, ((w - a.width) // 2, (h - a.height) // 2))
    return img


def build(out_dir):
    os.makedirs(out_dir, exist_ok=True)

    def save(img, name):
        img.save(os.path.join(out_dir, name))

    # Square 44x44 — taskbar, task switcher, list views.
    for scale, px in ((100, 44), (125, 55), (150, 66), (200, 88), (400, 176)):
        save(small(px) if px <= 88 else art(px), f"Square44x44Logo.scale-{scale}.png")
    for t in (16, 20, 24, 30, 32, 36, 40, 48, 60, 64, 72, 80, 96, 256):
        img = small(t) if t <= 48 else art(t)
        save(img, f"Square44x44Logo.targetsize-{t}.png")
        save(img, f"Square44x44Logo.targetsize-{t}_altform-unplated.png")

    # Square 150x150 — the Start tile.
    for scale, px in ((100, 150), (125, 188), (150, 225), (200, 300), (400, 600)):
        save(art(px), f"Square150x150Logo.scale-{scale}.png")

    # Wide 310x150 — the wide Start tile.
    for scale, (w, h) in ((100, (310, 150)), (125, (388, 188)), (150, (465, 225)),
                          (200, (620, 300)), (400, (1240, 600))):
        save(wide(w, h), f"Wide310x150Logo.scale-{scale}.png")

    # Store logo — the listing and the installer.
    for scale, px in ((100, 50), (125, 63), (150, 75), (200, 100), (400, 200)):
        save(art(px), f"StoreLogo.scale-{scale}.png")

    print(f"assets: {len(os.listdir(out_dir))} files in {out_dir}")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "layout", "Assets"))
