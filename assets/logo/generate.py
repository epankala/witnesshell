#!/usr/bin/env python3
"""Generate the witnesshell logo SVGs (and PNGs, if resvg-py is installed).

Usage: generate.py [MONO_BOLD.ttf]
The wordmark lockups need fontTools and a font (made with DejaVu Sans Mono
Bold); letters are converted to outlines so the SVGs have no font dependency.
"""
import math, pathlib, sys
OUT = pathlib.Path(__file__).resolve().parent
INK, DARK, LID = "#10203a", "#0a1020", "#0c0f1f"
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

def smooth(pts):
    """Closed Catmull-Rom curve; a point given as (x, y, 1) is a sharp tip."""
    N = len(pts); d = f"M{n(pts[0][0])} {n(pts[0][1])}"
    def tan(i):
        if len(pts[i]) > 2: return 0, 0
        a, b = pts[i-1], pts[(i+1) % N]
        return (b[0]-a[0])/6, (b[1]-a[1])/6
    for i in range(N):
        a, b = pts[i], pts[(i+1) % N]; ta, tb = tan(i), tan((i+1) % N)
        d += f"C{n(a[0]+ta[0])} {n(a[1]+ta[1])} {n(b[0]-tb[0])} {n(b[1]-tb[1])} {n(b[0])} {n(b[1])}"
    return d + "Z"

def lick(x, y, w, length, start, end, wig, f):
    """A flame whose heading (degrees, 90 = up) turns from start to end while
    it wiggles; f shrinks it for the hotter inner layers."""
    w, length, K = w*f, length*(.35+.65*f), 9
    left, right = [], []
    for i in range(K+1):
        t = i/K
        a = math.radians(start+(end-start)*min(1, t*1.25)+wig*math.sin(2*math.pi*t*1.05))
        hw = w/2*(1-t)**.85*(1+.25*math.sin(math.pi*t))
        if i < K:
            left.append((x-hw*math.sin(a), y-hw*math.cos(a)))
            right.append((x+hw*math.sin(a), y+hw*math.cos(a)))
            x += length/K*math.cos(a); y -= length/K*math.sin(a)
    return smooth(left+[(x, y, 1)]+right[::-1])

# x, y of the root, width, length, start heading, end heading, wiggle
BACK = [
    # crown
    (256,190,92,200,96,82,26),(206,196,76,150,104,100,-24),(310,194,78,166,80,96,28),
    # horns: long, sweeping out and hooking back in
    (150,232,92,262,140,62,14),(364,232,92,270,40,120,-14),
    # shoulders and sides
    (116,270,70,190,150,104,-18),(398,270,70,196,30,76,18),
    (84,312,66,186,166,104,14),(430,312,66,178,14,74,-14),
    (84,352,60,166,184,118,12),(430,352,60,174,-4,60,-12),
    # underside, raking outward
    (120,384,58,170,196,134,10),(394,384,58,178,-16,44,-10),
    (164,408,50,150,204,150,10),(350,408,50,158,-24,28,-10),
    (214,420,44,140,212,172,10),(300,420,44,146,-32,6,-10)]
SMALL_BACK = [(256,200,120,200,96,84,18),(150,240,130,262,140,62,10),(364,240,130,270,40,120,-10),
    (84,330,110,210,160,82,8),(428,330,110,216,20,98,-8),(130,380,120,180,190,96,6),(382,380,120,190,-10,84,-6)]
EMBERS = [(62,40,8),(222,-30,7),(332,-24,6),(458,36,7),(22,168,6),(494,160,6),(98,-30,5),(424,-34,5),(-20,240,5),(534,244,5)]
COLS = [("#3d0610",1.2),("#a80f1a",1),("#ec3414",.74),("#ff8a12",.48),("#ffd84a",.24)]

def flames(small):
    s = ""
    for c, f in COLS[1 if small else 0:]:
        ds = [lick(*t, f) for t in (SMALL_BACK if small else BACK)]
        s += f'<g fill="{c}">' + "".join(f'<path d="{d}"/>' for d in ds)
        # fire body behind the shell, so no gaps show between roots
        s += f'<ellipse cx="256" cy="312" rx="{n(192+8*f)}" ry="{n(130+10*f)}"/></g>\n'
    if not small:
        for x, y, r in EMBERS:
            d = f"M{x} {n(y-r*1.7)}Q{n(x+r*1.1)} {y} {x} {n(y+r*1.5)}Q{n(x-r*1.1)} {y} {x} {n(y-r*1.7)}Z"
            s += f'<path fill="#f4511e" d="{d}"/>'
    return s

def eye(x, y, r, side, mood, iris, dim, look):
    """One eye; side is -1 for the left eye of a pair, 1 for the right."""
    X = lambda dx: n(x+side*dx*r)        # +dx points away from the nose
    Y = lambda dy: n(y+dy*r)
    ir, pr = (.66, .46) if mood != "worried" else (.5, .27)
    lx, ly = x+look[0]*r, y+look[1]*r
    o = (f'<g opacity="{dim}"><ellipse cx="{n(x)}" cy="{n(y)}" rx="{n(r)}" ry="{n(r*1.12)}" fill="#fff6dc"/>'
         f'<circle cx="{n(lx)}" cy="{n(ly)}" r="{n(ir*r)}" fill="{iris}"/>'
         f'<circle cx="{n(lx)}" cy="{n(ly)}" r="{n(pr*r)}" fill="{DARK}"/>'
         f'<circle cx="{n(lx+.22*r)}" cy="{n(ly-.24*r)}" r="{n(.2*r)}" fill="#fff"/></g>\n')
    cid = f"e{n(x)}-{n(y)}".replace(".", "_")     # lids stay within their own eye
    o += f'<clipPath id="{cid}"><ellipse cx="{n(x)}" cy="{n(y)}" rx="{n(r+1)}" ry="{n(r*1.12+1)}"/></clipPath>'
    lid = lambda d: f'<path clip-path="url(#{cid})" fill="{LID}" d="{d}"/>\n'
    if mood == "friendly":               # cheeks push the lower lid up
        o += lid(f"M{X(-1.3)} {Y(1.5)}V{Y(1.0)}Q{X(0)} {Y(.12)} {X(1.3)} {Y(1.0)}V{Y(1.5)}Z")
    elif mood == "worried":              # upper lid and brow rise to the nose
        o += lid(f"M{X(-1.2)} {Y(-1.4)}V{Y(-1.12)}L{X(1.25)} {Y(-.12)}V{Y(-1.4)}Z")
        if r > 15:
            o += (f'<path d="M{X(-.75)} {Y(-1.42)}Q{X(.1)} {Y(-1.32)} {X(1.05)} {Y(-.72)}" fill="none" stroke="#8d7ba8" '
              f'stroke-opacity="{dim}" stroke-width="{n(r*.2)}" stroke-linecap="round"/>\n')
    else:                                # suspicious: lids narrowed, down to the nose
        o += lid(f"M{X(-1.2)} {Y(-1.4)}V{Y(.0)}L{X(1.25)} {Y(-.75)}V{Y(-1.4)}Z")
        o += lid(f"M{X(-1.2)} {Y(1.4)}V{Y(.8)}Q{X(0)} {Y(.62)} {X(1.2)} {Y(.8)}V{Y(1.4)}Z")
    return o

# centre x, y, eye radius, spacing, mood, iris, opacity, gaze, tilt of the pair
PAIRS = [
    (256,322,30,70,"friendly","#7a3b12",1,(0,.06),0),
    (137,322,19,46,"worried","#3f8fd0",1,(.12,.18),-5),
    (375,322,20,46,"suspicious","#c98a10",1,(-.34,.08),4),
    (186,278,14,32,"suspicious","#d0432f",.8,(.3,.1),-5),
    (328,277,14,31,"worried","#9a6be0",.8,(-.1,.15),5),
    (192,366,14,30,"friendly","#3c9d5b",.8,(.1,-.1),4),
    (322,367,15,32,"suspicious","#2f9aa8",.8,(-.3,.05),-4)]
SMALL_PAIRS = [(256,322,52,122,"friendly","#7a3b12",1,(0,.06),0)]

def eyes_svg(pairs):
    s = ""
    for x, y, r, gap, mood, iris, dim, look, tilt in pairs:
        es = "".join(eye(x+sd*gap/2, y, r, sd, mood, iris, dim, look) for sd in (-1, 1))
        s += f'<g transform="rotate({tilt} {x} {y})">{es}</g>\n'
    return s

def mark(small=False):
    k = 5 if small else 7
    up, dn = (-86, 80) if small else (-84, 82)
    sw = 15 if small else 9
    ux, dx = (24 if small else 22), (-14 if small else -16)
    upper = (f"M{L} {MY}{lip_path(up,ux,k)}C{R+26} {MY-50} {R-66} 168 {CX+40} 152"
             f"C{CX+34} 128 {CX-34} 128 {CX-40} 152C{L+66} 168 {L-26} {MY-50} {L} {MY}Z")
    lower = f"M{L} {MY}{lip_path(dn,dx,k)}C{R+18} {MY+52} {R-92} 452 {CX} 454C{L+92} 452 {L-18} {MY+52} {L} {MY}Z"
    # inside of the shell, seen through the gap
    def arc(d): return f"M{L} {MY}"+"C"+f"{L+50} {n(MY+d*1.33)} {R-50} {n(MY+d*1.33)} {R} {MY}"
    inside = arc(up-6)+f"C{R-50} {n(MY+(dn+14)*1.33)} {L+50} {n(MY+(dn+14)*1.33)} {L} {MY}Z"
    band = "" if small else (f'<path d="M{L+42} 258Q{CX} 138 {R-42} 258" '
        'fill="none" stroke="#baf5e6" stroke-opacity=".5" stroke-width="9" stroke-linecap="round"/>\n')
    j = 'stroke-linejoin="round" stroke-linecap="round"'
    return f'''<g transform="translate(256 256) scale({.85 if small else .775}) translate(-256 {-256 if small else -228})"><defs>
<linearGradient id="u" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#1f8f96"/><stop offset="1" stop-color="#5fd6c8"/></linearGradient>
<linearGradient id="d" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#42bdb4"/><stop offset="1" stop-color="#16697a"/></linearGradient>
</defs>
{flames(small)}<path d="{inside}" fill="{LID}" stroke="{INK}" stroke-width="{sw}" {j}/>
{eyes_svg(SMALL_PAIRS if small else PAIRS)}<path d="{lower}" fill="url(#d)" stroke="{INK}" stroke-width="{sw}" {j}/>
<path d="{"" if small else ribs(dn,450,k,.55)}" fill="none" stroke="{INK}" stroke-opacity=".55" stroke-width="{sw*.6:.1f}" {j}/>
<path d="{upper}" fill="url(#u)" stroke="{INK}" stroke-width="{sw}" {j}/>
{band}<path d="{ribs(up,154,k,.5)}" fill="none" stroke="{INK}" stroke-opacity=".55" stroke-width="{sw*.6:.1f}" {j}/>
</g>
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
        t, x = wordmark(sys.argv[1], ink, 190, 520, 384)
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
