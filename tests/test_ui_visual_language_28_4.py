"""Bounded SVG and semantic visual summary contracts for the local UI."""

from pathlib import Path
from hashlib import sha256
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend/index.html").read_text(encoding="utf-8")
CSS = (ROOT / "frontend/style.css").read_text(encoding="utf-8")
APP = (ROOT / "frontend/app.js").read_text(encoding="utf-8")
LICENSE = ROOT / "docs/licenses/lucide-static-1.59.0-LICENSE"
ICONS = {
    "house", "flask-conical", "files", "scan-line", "clipboard-list",
    "activity", "search", "link", "shield-alert", "folder-search",
    "circle-help", "triangle-alert", "circle-x",
    "panel-left-close", "panel-left-open",
}
PATH_DIGESTS = {
    "house": "745c1bb02f199cd991e6bcbdc6e6d2724f352c462d6007f76b5e3429e1f071f5",
    "flask-conical": "7dd88e57aa049315f315f1c78a9126cc915a3c8d1ecc03f92988f03b72628417",
    "files": "61451d0748a26e3714b76c36ff5a4797eeb7adfe9f83988d92130b9d08ff640b",
    "scan-line": "e9d7883d1970bdae6d7eae8c626ef4829cbf8d5039749d818b61c5f23513f826",
    "clipboard-list": "9b1edddff298dde90eaf3e2997c0bfef596983c8df83e0229b9c3e3cfc2ad92c",
    "activity": "1f28d260b5be24e0d016f1c9b592e69c3bdbc3266089255560adc363fbb11771",
    "search": "a92c3427a2028b5f59dc0c176e1e2b7e64d2947b49405226870fdea62c90487c",
    "link": "9019798a6e28264025ce3f545af42f8deebd76355ce4b4c1a78a51cd5df4f08d",
    "shield-alert": "ee0e09b0a1751f53a34b7a840c2320b389713441c2a9d51be5392b43e14de8a9",
    "folder-search": "83a415850f5a9f2d34e8e0304d25360e9f6db3bd1a79fb8371274e84b72572e4",
    "circle-help": "a480ac7a6a3f9591f8404504f2189ecf34d01018e25607041c71261f66f50545",
    "triangle-alert": "d30df6d5df4ed86dbe908d4779876babe9a5a668d23503ba4e06911f88c103bf",
    "circle-x": "2bc44a6b56f45963ab5a915e80e6084f2a3e4e9560008e397a6ac410871d5523",
    "panel-left-close": "4a1094f7f22f79c99b93fc6ee007ce4795abdf57abb401c0f654d1b34f898293",
    "panel-left-open": "742855cb66c064d089eea6313ca8310c5e3305199e6d1f6621b15b1c9e7277a9",
}


def test_bounded_tracked_lucide_sprite_and_attribution():
    assert LICENSE.is_file()
    assert "ISC License" in LICENSE.read_text(encoding="utf-8")
    assert "The MIT License" in LICENSE.read_text(encoding="utf-8")
    svg = HTML[HTML.index('<svg id="icon-sprite"'):HTML.index('</svg>') + 6]
    root = ElementTree.fromstring(svg)
    ns = "{http://www.w3.org/2000/svg}"
    assert {child.get("id").removeprefix("icon-") for child in root} == ICONS
    allowed_tags = {"svg", "symbol", "path", "circle", "rect", "line", "polyline", "polygon", "ellipse"}
    allowed_attrs = {"id", "viewBox", "fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin",
                     "d", "cx", "cy", "r", "x", "y", "x1", "y1", "x2", "y2", "rx", "ry", "width", "height", "points",
                     "aria-hidden", "focusable", "xmlns", "class"}
    for node in root.iter():
        assert node.tag.removeprefix(ns) in allowed_tags
        assert set(node.attrib) <= allowed_attrs
        assert not node.attrib.get("href")
    assert "currentColor" in svg
    for symbol in root:
        name = symbol.get("id").removeprefix("icon-")
        canonical = "|".join(
            child.tag.removeprefix(ns) + ":" + ";".join(f"{key}={value}" for key, value in sorted(child.attrib.items()))
            for child in symbol
        )
        assert sha256(canonical.encode()).hexdigest() == PATH_DIGESTS[name]


def test_visual_cues_keep_text_and_safe_flow():
    assert 'id="analysis-flow"' in HTML
    assert 'class="flow-step"' in HTML
    assert HTML.count('class="action-card"') == 3
    assert 'aria-hidden="true" focusable="false"' in HTML
    assert 'function icon(' in APP
    assert 'summary-icon' in APP
    assert 'risk-distribution' not in HTML
    for forbidden in ("<script src=\"https:", "innerHTML", "insertAdjacentHTML", "localStorage", "sessionStorage"):
        assert forbidden not in HTML + APP
    assert "@media (prefers-reduced-motion: reduce)" in CSS
