from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent


def load_font(size: int, bold: bool = False):
    candidates = []
    if bold:
        candidates.extend(
            [
                "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
                "/Library/Fonts/Arial Bold.ttf",
            ]
        )
    candidates.extend(
        [
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/Library/Fonts/Arial.ttf",
        ]
    )
    for path in candidates:
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


TITLE_FONT = load_font(38, bold=True)
SUBTITLE_FONT = load_font(22)
BOX_TITLE_FONT = load_font(26, bold=True)
BOX_BODY_FONT = load_font(20)
FOOTER_FONT = load_font(20, bold=True)


def draw_text_centered(draw, box, text, font, fill):
    x1, y1, x2, y2 = box
    lines = text.split("\n")
    line_gap = 6
    heights = []
    widths = []
    for line in lines:
        bbox = draw.textbbox((0, 0), line, font=font)
        widths.append(bbox[2] - bbox[0])
        heights.append(bbox[3] - bbox[1])
    total_h = sum(heights) + line_gap * (len(lines) - 1)
    y = y1 + ((y2 - y1) - total_h) / 2
    for line, w, h in zip(lines, widths, heights):
        x = x1 + ((x2 - x1) - w) / 2
        draw.text((x, y), line, font=font, fill=fill)
        y += h + line_gap


def draw_box(draw, coords, title, body, color):
    draw.rounded_rectangle(coords, radius=24, fill=color, outline="#333333", width=3)
    x1, y1, x2, y2 = coords
    draw_text_centered(draw, (x1 + 10, y1 + 8, x2 - 10, y1 + 48), title, BOX_TITLE_FONT, "#202020")
    draw_text_centered(draw, (x1 + 10, y1 + 48, x2 - 10, y2 - 10), body, BOX_BODY_FONT, "#202020")


def center(box):
    x1, y1, x2, y2 = box
    return ((x1 + x2) // 2, (y1 + y2) // 2)


def draw_arrow(draw, src_box, dst_box, label=None):
    sx, sy = center(src_box)
    tx, ty = center(dst_box)
    draw.line((sx, sy, tx, ty), fill="#4d4d4d", width=4)
    dx = tx - sx
    dy = ty - sy
    length = max((dx * dx + dy * dy) ** 0.5, 1)
    ux = dx / length
    uy = dy / length
    arrow_len = 18
    px = -uy
    py = ux
    tip = (tx, ty)
    left = (tx - ux * arrow_len - px * 8, ty - uy * arrow_len - py * 8)
    right = (tx - ux * arrow_len + px * 8, ty - uy * arrow_len + py * 8)
    draw.polygon([tip, left, right], fill="#4d4d4d")
    if label:
        mx = (sx + tx) // 2
        my = (sy + ty) // 2 - 18
        bbox = draw.textbbox((0, 0), label, font=SUBTITLE_FONT)
        draw.rounded_rectangle(
            (mx - 8, my - 4, mx + (bbox[2] - bbox[0]) + 8, my + (bbox[3] - bbox[1]) + 4),
            radius=8,
            fill="white",
            outline="#cccccc",
            width=1,
        )
        draw.text((mx, my), label, font=SUBTITLE_FONT, fill="#303030")


def save_image_and_pdf(image: Image.Image, stem: str):
    png_path = ROOT / f"{stem}.png"
    pdf_path = ROOT / f"{stem}.pdf"
    image.save(png_path, format="PNG")
    image.save(pdf_path, format="PDF", resolution=150.0)
    return pdf_path, png_path


def build_runtime_flow():
    width, height = 1800, 900
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    
    """ client.py 发请求，transport.py 负责把请求通过 isotp.py + bus.py 送出去，
    gateway.py 决定是否转发，server.py 接收后交给 ecu.py 处理，最后再把结果返回。
    """

    draw.text((460, 20), "Diagram 1: Core Runtime Flow", font=TITLE_FONT, fill="#202020")
    draw.text((350, 68), "只看最核心的软件执行链路：谁发请求，谁转发，谁处理，谁保存状态", font=SUBTITLE_FONT, fill="#444444")

    boxes = {
        "client": ((60, 340, 320, 500), "client.py", "构造 UDS 请求\n像 tester / attacker 一样发 0x10 / 0x27 / 0x2E", "#fff0c9"),
        "transport": ((390, 340, 700, 500), "transport.py", "把 request / response\n通过 ISO-TP + CAN 的方式来回传递", "#ffe0cc"),
        "gateway": ((780, 340, 1060, 500), "gateway.py", "决定请求是否转发\n模拟 routed diagnostics", "#ffd8e8"),
        "server": ((1140, 340, 1400, 500), "server.py", "接收 payload\n把请求交给 ECU 状态机", "#ffd8e8"),
        "ecu": ((1480, 300, 1740, 540), "ecu.py", "真正的 ECU 逻辑\n维护 session / unlock / lockout / write state", "#ffd8e8"),
        "protocol": ((180, 620, 470, 780), "protocol.py", "定义 UDS request / response\n负责编码和解析", "#fff0c9"),
        "isotp": ((560, 620, 850, 780), "isotp.py", "把 payload 分帧和重组\n模拟 ISO-TP", "#ffe0cc"),
        "bus": ((940, 620, 1230, 780), "bus.py", "模拟内存 CAN 总线\n记录 trace 和 arbitration id", "#ffe0cc"),
    }

    for _, spec in boxes.items():
        draw_box(draw, spec[0], spec[1], spec[2], spec[3])

    draw_arrow(draw, boxes["client"][0], boxes["transport"][0], "send request")
    draw_arrow(draw, boxes["transport"][0], boxes["gateway"][0], "route frames")
    draw_arrow(draw, boxes["gateway"][0], boxes["server"][0], "forward")
    draw_arrow(draw, boxes["server"][0], boxes["ecu"][0], "handle payload")
    draw_arrow(draw, boxes["client"][0], boxes["protocol"][0], "use")
    draw_arrow(draw, boxes["transport"][0], boxes["isotp"][0], "use")
    draw_arrow(draw, boxes["transport"][0], boxes["bus"][0], "use")

    draw.text((470, 835), "主链路：client -> transport -> gateway -> server -> ecu", font=FOOTER_FONT, fill="#202020")
    return image


def build_analysis_flow():
    width, height = 2400, 1400
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)

    draw.text((620, 20), "Diagram 2: Clean Analysis Flow Around The Core", font=TITLE_FONT, fill="#202020")
    draw.text((410, 68), "第二层只讲：哪些模块建立在核心运行链路之上，以及它们各自负责什么。这里只保留必要关系。", font=SUBTITLE_FONT, fill="#444444")

    boxes = {
        "main": ((900, 130, 1500, 270), "main.py", "命令行入口\n把各个模块的结果打印出来", "#d8ecff"),
        "scenarios": ((120, 420, 600, 600), "scenarios.py", "把核心运行链路拼成攻击与补丁场景\n未授权写 / replay / patch demo", "#dff6dd"),
        "differential": ((690, 420, 1170, 600), "differential.py", "比较两种 backend 是否语义一致\n当前比较 direct 与 gateway-routed", "#d7f4f7"),
        "timing": ((1260, 420, 1740, 600), "timing.py", "估计 handler latency\njitter / patch delay", "#e4dcff"),
        "fleet": ((1830, 420, 2310, 600), "fleet.py", "把单车安全结论提升到车队层面\nOTA-only vs hotpatch-first", "#e4dcff"),
        "core": ((720, 760, 1680, 980), "Core Runtime", "client.py + transport.py + gateway.py + server.py + ecu.py\nprotocol.py + isotp.py + bus.py", "#f4f4f4"),
        "fuzzing": ((200, 1120, 760, 1280), "fuzzing.py", "生成系统化 fuzzing corpus\npayload / state sequence / ISO-TP anomaly", "#d7f4f7"),
        "frameworks": ((920, 1120, 1480, 1280), "frameworks.py", "检查 python-can / can-isotp / udsoncan\n为以后接 vcan 和真实协议栈做准备", "#e4dcff"),
        "tests": ((1640, 1120, 2200, 1280), "tests/*.py", "自动验证模块是否正常工作\n当前所有测试都从这里跑", "#f0f0f0"),
    }

    for _, spec in boxes.items():
        draw_box(draw, spec[0], spec[1], spec[2], spec[3])

    draw_arrow(draw, boxes["main"][0], boxes["scenarios"][0], "run / print")
    draw_arrow(draw, boxes["main"][0], boxes["differential"][0], None)
    draw_arrow(draw, boxes["main"][0], boxes["timing"][0], None)
    draw_arrow(draw, boxes["main"][0], boxes["fleet"][0], None)

    draw_arrow(draw, boxes["scenarios"][0], boxes["core"][0], "build experiments")
    draw_arrow(draw, boxes["differential"][0], boxes["core"][0], "compare behavior")
    draw_arrow(draw, boxes["timing"][0], boxes["core"][0], "estimate overhead")
    draw_arrow(draw, boxes["fleet"][0], boxes["core"][0], "reuse conclusions")

    draw_arrow(draw, boxes["fuzzing"][0], boxes["differential"][0], "provide case corpus")
    draw_arrow(draw, boxes["frameworks"][0], boxes["differential"][0], "future external adapters")
    draw_arrow(draw, boxes["tests"][0], boxes["core"][0], "verify")

    draw.text((700, 1345), "理解顺序建议：先看 Diagram 1 的主链路，再看这张图理解外围模块如何依赖主链路。", font=FOOTER_FONT, fill="#202020")
    return image


def main():
    runtime_image = build_runtime_flow()
    runtime_pdf, runtime_png = save_image_and_pdf(runtime_image, "software_only_runtime_flow")

    analysis_image = build_analysis_flow()
    analysis_pdf, analysis_png = save_image_and_pdf(analysis_image, "software_only_analysis_modules_clean")

    print(runtime_pdf)
    print(runtime_png)
    print(analysis_pdf)
    print(analysis_png)


if __name__ == "__main__":
    main()
