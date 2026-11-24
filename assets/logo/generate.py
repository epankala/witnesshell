#!/usr/bin/env python3
"""Generate the witnesshell logo SVGs (and PNGs, if resvg-py is installed).

Usage: generate.py [MONO_BOLD.ttf]
The wordmark lockups need fontTools and a font (made with DejaVu Sans Mono
Bold); letters are converted to outlines so the SVGs have no font dependency.
"""
import math, pathlib, sys
OUT = pathlib.Path(__file__).resolve().parent
INK, DARK = "#10203a", "#0a1020"
L, R, CX = 58, 454, 256      # corners of the mouth
MY = 318                     # height of the corners
n = lambda v: f"{v:.1f}".rstrip("0").rstrip(".")

def lip(t, depth):           # t in 0..1 along the mouth
    return L + (R-L)*(1-math.cos(math.pi*t))/2, MY + depth*math.sin(math.pi*t)

def lip_path(depth, bulge, k):
    """Scalloped edge, left to right, after the pen is at the left corner."""
    s = ""
    for i in range(k):
        x0, y0 = lip(i/k, depth); x1, y1 = lip((i+1)/k, depth)
        b = bulge*math.sin(math.pi*(i+.5)/k)
        s += f"C{n(x0+(x1-x0)*.15)} {n(y0+b+(y1-y0)*.15)} {n(x1-(x1-x0)*.15)} {n(y1+b-(y1-y0)*.15)} {n(x1)} {n(y1)}"
    return s

def ribs(depth, apex, k, belly):
    s = ""
    for i in range(1, k):
        x, y = lip(i/k, depth)
        ax = CX + (x-CX)*.10
        s += f"M{n(x)} {n(y)}Q{n(CX+(x-CX)*.88)} {n(y+(apex-y)*belly)} {n(ax)} {n(apex)}"
    return s

def tongue(x, y, w, h, sway, f=1.0):
    """One upward flame, base centre x,y; f shrinks it for the inner layers."""
    w, h, sway = w*f, h*f, sway*f
    m = -1 if sway < 0 else 1            # drawn leaning right, mirrored if needed
    sway = abs(sway)
    P = lambda dx, dy: f"{n(x+m*dx)} {n(y-dy)}"
    return (f"M{P(-w/2,0)}C{P(-w/2,h*.4)} {P(sway-w*.12,h*.5)} {P(sway,h)}"
            f"C{P(sway+w*.16,h*.7)} {P(w/2,h*.4)} {P(w/2,0)}Z")

# x, y of the base, width, height, lean
BACK = [(62,351,84,206,-18),(122,262,96,196,-16),(192,206,92,158,-10),
        (262,200,92,186,10),(330,206,92,150,12),(396,262,96,212,18),(450,351,84,192,18)]
SMALL_BACK = [(62,351,96,210,-18),(160,250,120,208,-16),(262,200,110,180,10),(362,250,120,216,16),(450,351,96,220,18)]
COLS = [("#e5352b",1),("#ff8a1f",.76),("#ffd23f",.52)]

def flames(ts):
    s = ""
    for c, f in COLS:
        rx, ry = 236-(1-f)*42, 138-(1-f)*38      # body of fire under the shell
        ds = [f"M{n(CX-rx)} 350A{n(rx)} {n(ry)} 0 0 0 {n(CX+rx)} 350Z"]
        ds += [tongue(*t, f) for t in ts]
        s += f'<g fill="{c}">' + "".join(f'<path d="{d}"/>' for d in ds) + "</g>\n"
    return s

def mark(small=False):
    k = 5 if small else 7
    up, dn = (-80, 76) if small else (-64, 62)
    sw = 15 if small else 9
    ux, dx = (24 if small else 22), (-14 if small else -16)
    upper = (f"M{L} {MY}{lip_path(up,ux,k)}C{R+26} {MY-50} {R-66} 168 {CX+40} 152"
             f"C{CX+34} 128 {CX-34} 128 {CX-40} 152C{L+66} 168 {L-26} {MY-50} {L} {MY}Z")
    lower = f"M{L} {MY}{lip_path(dn,dx,k)}C{R+18} {MY+52} {R-92} 452 {CX} 454C{L+92} 452 {L-18} {MY+52} {L} {MY}Z"
    # inside of the shell, seen through the gap
    def arc(d): return f"M{L} {MY}"+"C"+f"{L+50} {n(MY+d*1.33)} {R-50} {n(MY+d*1.33)} {R} {MY}"
    inside = arc(up-6)+f"C{R-50} {n(MY+(dn+14)*1.33)} {L+50} {n(MY+(dn+14)*1.33)} {L} {MY}Z"
    band = "" if small else (f'<path d="M{L+42} 268Q{CX} 152 {R-42} 268M{L+104} 214Q{CX} 144 {R-104} 214" '
        'fill="none" stroke="#baf5e6" stroke-opacity=".5" stroke-width="9" stroke-linecap="round"/>\n')
    e = 1.45 if small else 1.08
    eyes, off = "", 62 if small else 54
    for x, side in ((CX-off,-1),(CX+off,1)):
        rx, ry, y = 37*e, 43*e, 316
        eyes += f'''<g><ellipse cx="{x}" cy="{y}" rx="{n(rx)}" ry="{n(ry)}" fill="#fff6dc"/>
<circle cx="{n(x-side*5)}" cy="{n(y+3)}" r="{n(25*e)}" fill="#7a3b12"/>
<circle cx="{n(x-side*5)}" cy="{n(y+3)}" r="{n(18*e)}" fill="{DARK}"/>
<circle cx="{n(x-side*5+8)}" cy="{n(y-7)}" r="{n(8.5*e)}" fill="#fff"/>
''' + ("" if small else f'<circle cx="{n(x-side*5-8)}" cy="{n(y+12)}" r="4" fill="#fff"/>\n') + "</g>\n"
    # lower lids: cheeks pushing up, so the eyes smile
    low = 16 if small else 0
    for x in (CX-off, CX+off):
        eyes += f'<path fill="{DARK}" d="M{x-off} 400V{366+low}Q{x} {322+low} {x+off} {366+low}V400Z"/>\n'
    j = 'stroke-linejoin="round" stroke-linecap="round"'
    return f'''<defs>
<linearGradient id="u" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#1f8f96"/><stop offset="1" stop-color="#5fd6c8"/></linearGradient>
<linearGradient id="d" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#42bdb4"/><stop offset="1" stop-color="#16697a"/></linearGradient>
<radialGradient id="g" cx=".5" cy=".55" r=".5"><stop offset="0" stop-color="#2b2140"/><stop offset="1" stop-color="{DARK}"/></radialGradient>
</defs>
{flames(SMALL_BACK if small else BACK)}<path d="{inside}" fill="{DARK if small else 'url(#g)'}" stroke="{INK}" stroke-width="{sw}" {j}/>
{eyes}<path d="{lower}" fill="url(#d)" stroke="{INK}" stroke-width="{sw}" {j}/>
<path d="{"" if small else ribs(dn,450,k,.55)}" fill="none" stroke="{INK}" stroke-opacity=".55" stroke-width="{sw*.6:.1f}" {j}/>
<path d="{upper}" fill="url(#u)" stroke="{INK}" stroke-width="{sw}" {j}/>
{band}<path d="{ribs(up,154,k,.5)}" fill="none" stroke="{INK}" stroke-opacity=".55" stroke-width="{sw*.6:.1f}" {j}/>
'''

def svg(body, w=512, h=512):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" aria-label="witnesshell">\n'
            f'<title>witnesshell</title>\n{body}</svg>\n')

def wordmark(font, ink, size, x, y):
    from fontTools.ttLib import TTFont
    from fontTools.pens.svgPathPen import SVGPathPen
    from fontTools.pens.transformPen import TransformPen
    f = TTFont(font); gs = f.getGlyphSet(); cm = f.getBestCmap(); k = size/f["head"].unitsPerEm
    out, parts = "", {"a":"", "s":"", "h":""}
    for i, c in enumerate("witnesshell"):
        g = gs[cm[ord(c)]]; p = SVGPathPen(gs, ntos=n)
        g.draw(TransformPen(p, (k,0,0,-k,x,y))); x += g.width*k*.97
        parts["a" if i < 6 else "s" if i == 6 else "h"] += p.getCommands()
    # the shared "s" belongs to witneSS, Shell; "hell" burns
    out += (f'<defs><linearGradient id="f" gradientUnits="userSpaceOnUse" x1="0" x2="0" y1="{n(y-size*.76)}" y2="{n(y)}">'
            '<stop offset="0" stop-color="#e5352b"/><stop offset="1" stop-color="#ff9a1f"/></linearGradient></defs>\n')
    out += f'<path fill="{ink}" d="{parts["a"]}"/>\n<path fill="#23a39f" d="{parts["s"]}"/>\n<path fill="url(#f)" d="{parts["h"]}"/>\n'
    return out, x

files = {"witnesshell.svg": svg(mark()), "witnesshell-icon.svg": svg(mark(True))}
if len(sys.argv) > 1:
    for name, ink in (("light", INK), ("dark", "#f3f6fa")):
        t, x = wordmark(sys.argv[1], ink, 190, 520, 366)
        files[f"witnesshell-wordmark-{name}.svg"] = svg(mark()+t, round(x+30))
for name, s in files.items(): (OUT/name).write_text(s)
try:
    import resvg_py
except ImportError:
    sys.exit("SVGs written; install resvg-py for PNGs")
def png(src, dst, w):
    (OUT/dst).write_bytes(bytes(resvg_py.svg_to_bytes(svg_string=files[src], width=w)))
png("witnesshell.svg", "witnesshell-1024.png", 1024)
png("witnesshell.svg", "witnesshell-256.png", 256)
for w in (16, 32, 64): png("witnesshell-icon.svg", f"witnesshell-icon-{w}.png", w)
for v in ("light", "dark"):
    if f"witnesshell-wordmark-{v}.svg" in files:
        png(f"witnesshell-wordmark-{v}.svg", f"witnesshell-wordmark-{v}.png", 1600)
