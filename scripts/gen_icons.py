"""
Generate Kosh app icons. The mark is drawn procedurally (a vault door in the brand
indigo #6366F1) — no external logo asset is used, matching the code-drawn Brandmark in
the UI. Re-run this after changing the mark to regenerate every platform's icon.

Requires Pillow:  pip install pillow

Produces:
  - cmd/localvault/build/appicon.png          (1024x1024, used by Wails for all platforms)
  - cmd/localvault/build/windows/icon.ico     (multi-size: 256,128,64,48,32,16)
  - cmd/localvault/build/darwin/               (macOS .icns source sizes)
"""

import struct, zlib, io, sys, os
from PIL import Image, ImageDraw, ImageFilter
import math

APPICON   = "cmd/localvault/build/appicon.png"
WIN_ICO   = "cmd/localvault/build/windows/icon.ico"

def make_vault_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # ── background: deep dark navy rounded square ──
    pad = int(size * 0.03)
    r = int(size * 0.22)
    draw.rounded_rectangle([pad, pad, size - pad, size - pad],
                            radius=r,
                            fill=(13, 17, 35, 255))

    # ── subtle indigo gradient overlay (simulate with a bright inner ring) ──
    glow_pad = int(size * 0.05)
    draw.rounded_rectangle([glow_pad, glow_pad, size - glow_pad, size - glow_pad],
                            radius=int(size * 0.18),
                            fill=(24, 28, 54, 255))

    s = size / 256.0

    # ── vault door body ──
    vx1 = int(44 * s); vy1 = int(52 * s)
    vx2 = int(212 * s); vy2 = int(204 * s)
    vr  = int(18 * s)
    draw.rounded_rectangle([vx1, vy1, vx2, vy2], radius=vr,
                            fill=(32, 38, 74, 255),
                            outline=(99, 102, 241, 255),
                            width=max(2, int(3 * s)))

    # ── dial ring (outer) ──
    cx = int(128 * s); cy = int(120 * s)
    dr_outer = int(46 * s)
    draw.ellipse([cx - dr_outer, cy - dr_outer, cx + dr_outer, cy + dr_outer],
                 fill=(20, 24, 52, 255),
                 outline=(99, 102, 241, 255),
                 width=max(2, int(3 * s)))

    # ── dial ring (inner highlight) ──
    dr_inner = int(32 * s)
    draw.ellipse([cx - dr_inner, cy - dr_inner, cx + dr_inner, cy + dr_inner],
                 fill=(28, 33, 64, 255),
                 outline=(79, 82, 200, 200),
                 width=max(1, int(2 * s)))

    # ── dial notches at 12, 3, 6, 9 o'clock ──
    notch_outer = int(40 * s)
    notch_inner = int(33 * s)
    for angle_deg in [0, 90, 180, 270]:
        angle = math.radians(angle_deg - 90)
        nx1 = cx + int(notch_inner * math.cos(angle))
        ny1 = cy + int(notch_inner * math.sin(angle))
        nx2 = cx + int(notch_outer * math.cos(angle))
        ny2 = cy + int(notch_outer * math.sin(angle))
        draw.line([nx1, ny1, nx2, ny2], fill=(148, 150, 255, 255), width=max(2, int(3 * s)))

    # ── dial center dot ──
    dc = int(6 * s)
    draw.ellipse([cx - dc, cy - dc, cx + dc, cy + dc], fill=(99, 102, 241, 255))

    # ── three locking bolts (right side) ──
    bolt_x = int(186 * s)
    bolt_r = int(7 * s)
    for bolt_y in [int(82 * s), int(120 * s), int(158 * s)]:
        draw.ellipse([bolt_x - bolt_r, bolt_y - bolt_r,
                      bolt_x + bolt_r, bolt_y + bolt_r],
                     fill=(99, 102, 241, 255),
                     outline=(148, 150, 255, 200),
                     width=max(1, int(2 * s)))

    # ── handle (left side) ──
    hx = int(62 * s); hy = int(104 * s)
    hw = int(12 * s); hh = int(32 * s)
    hr = int(5 * s)
    draw.rounded_rectangle([hx, hy, hx + hw, hy + hh], radius=hr,
                            fill=(99, 102, 241, 255))

    # ── shield / keyhole at bottom ──
    kx = cx; ky = int(172 * s)
    kr_top = int(12 * s)
    draw.ellipse([kx - kr_top, ky - kr_top, kx + kr_top, ky + kr_top],
                 fill=(99, 102, 241, 255))
    keyhole_w = int(7 * s); keyhole_h = int(14 * s)
    draw.rectangle([kx - keyhole_w // 2, ky, kx + keyhole_w // 2, ky + keyhole_h],
                   fill=(99, 102, 241, 255))

    # ── thin accent line under vault ──
    line_y = int(218 * s)
    line_x1 = int(80 * s); line_x2 = int(176 * s)
    lw = max(2, int(3 * s))
    draw.rounded_rectangle([line_x1, line_y, line_x2, line_y + lw],
                            radius=lw,
                            fill=(99, 102, 241, 180))

    return img


print("Generating vault icon at all required sizes…")

icon_1024 = make_vault_icon(1024)
icon_1024.save(APPICON)
print(f"✓ {APPICON}")

ico_sizes = [256, 128, 64, 48, 32, 16]
frames = [make_vault_icon(s) for s in ico_sizes]
frames[0].save(
    WIN_ICO,
    format="ICO",
    sizes=[(s, s) for s in ico_sizes],
    append_images=frames[1:]
)
print(f"✓ {WIN_ICO}")

darwin_dir = "cmd/localvault/build/darwin"
os.makedirs(darwin_dir, exist_ok=True)
for sz in [1024, 512, 256, 128, 64, 32, 16]:
    make_vault_icon(sz).save(os.path.join(darwin_dir, f"icon_{sz}x{sz}.png"))
print(f"✓ darwin PNG set → {darwin_dir}/")

print("\nAll icons generated. Done.")
