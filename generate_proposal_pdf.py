#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Generate a one-page Chinese PDF proposal for the MoonGuard project.

Run: `python generate_proposal_pdf.py` from the repo root. The output is
written to `MoonGuard_Project_Proposal.pdf`.

Pure stdlib + reportlab so it works on any machine with `pip install
reportlab`.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)
from reportlab.lib.enums import TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os


def find_chinese_font():
    """Try to register a CJK-capable TTF so the PDF renders Chinese.

    We scan common Windows / Linux locations first; if none works the
    document falls back to Helvetica and the Chinese text is replaced by
    ``?`` so the rest of the page still renders.
    """
    candidates = [
        ("MicrosoftYaHei", r"C:\Windows\Fonts\msyh.ttc"),
        ("SimSun", r"C:\Windows\Fonts\simsun.ttc"),
        ("SimHei", r"C:\Windows\Fonts\simhei.ttf"),
        ("NotoSansCJK", "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
        ("NotoSansCJK", "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc"),
        ("SourceHanSans", "/usr/share/fonts/opentype/source-han-sans/SourceHanSansCN-Regular.otf"),
        ("WenQuanYi", "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc"),
    ]
    for name, path in candidates:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont(name, path))
                return name
            except Exception:
                continue
    return None


def main() -> int:
    pdf_path = "MoonGuard_Project_Proposal.pdf"
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=1.4 * cm,
        bottomMargin=1.4 * cm,
    )

    font_name = find_chinese_font()
    print(f"Using font: {font_name or 'Helvetica (CJK fallback)'}")

    base = getSampleStyleSheet()
    title_style = ParagraphStyle(
        name="TitleCN",
        parent=base["Title"],
        fontName=font_name or "Helvetica",
        fontSize=18,
        leading=22,
        alignment=TA_LEFT,
        spaceAfter=8,
    )
    h2 = ParagraphStyle(
        name="H2CN",
        parent=base["Heading2"],
        fontName=font_name or "Helvetica",
        fontSize=12,
        leading=15,
        spaceBefore=6,
        spaceAfter=3,
    )
    body = ParagraphStyle(
        name="BodyCN",
        parent=base["BodyText"],
        fontName=font_name or "Helvetica",
        fontSize=9,
        leading=12,
        spaceAfter=3,
    )

    flow = []
    flow.append(Paragraph("MoonGuard 项目申报书", title_style))
    flow.append(Spacer(1, 4))

    sections = [
        ("一、项目名称", "MoonGuard — MoonBit 供应链安全工具链"),
        ("二、项目简介", "MoonGuard 是用纯 MoonBit 实现的供应链安全工具链，提供 Ed25519 包签名与验签、SHA-256 清单完整性校验、JSON+PEM 可信公钥管理、Levenshtein 与同形（homoglyph）双模式 typosquat 检测、CVSS 风格 0–10 风险评分的 JSON 安全审计报告，附带 9 子命令的 moon_guard CLI。"),
        ("三、项目方向与适用场景", "方向：MoonBit 包供应链安全（包来源可信 + 清单完整性 + typosquat 检测）。适用：开发者发布前签名验证、用户安装前审计、CI/CD 集成、批量仓库风险扫描。"),
    ]
    for title, text in sections:
        flow.append(Paragraph(title, h2))
        flow.append(Paragraph(text, body))

    flow.append(Paragraph("四、核心功能", h2))
    features = [
        ["lib/manifest", "纯 MoonBit SHA-256、清单生成与校验"],
        ["lib/crypto", "Ed25519（RFC 8032）+ SHA-512 + field 算术"],
        ["lib/trust", "Full / Partial / Untrusted 分级 + PEM / JSON 持久化"],
        ["lib/verify", "audit 全链路（integrity + signature + trust）+ typosquat 严格检测"],
        ["lib/report", "0–10 风险评分 + JSON 安全报告"],
        ["cmd/main", "9 子命令 CLI：keygen / sign / verify / trust / typosquat / manifest / hash / audit / version"],
    ]
    t = Table(features, colWidths=[3.2 * cm, 13.0 * cm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), font_name or "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("BOX", (0, 0), (-1, -1), 0.5, "#888888"),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, "#cccccc"),
    ]))
    flow.append(t)
    flow.append(Spacer(1, 4))

    sections2 = [
        ("五、项目属性", "原创项目 — SHA-256 / Ed25519 / Levenshtein 全部按公开 RFC（6234 / 8032）与算法规范独立实现，不移植自其他项目，无闭源代码，无授权争议。"),
        ("六、GitHub / Gitlink 仓库", "GitHub：https://github.com/chenzehaoo/MoonGUARD<br/>Gitlink：https://gitlink.org.cn/sharp/MoonGuard<br/>默认分支：main"),
        ("七、交付物", "核心 lib + CLI + 83+ 单元 / 端到端 / fuzz / bench 测试 + 跨平台 CI（ubuntu/macos/windows × wasm/native）+ examples/basic_audit 可复现 demo；通过 moon check / moon info / moon test 三连验证。"),
        ("八、编译与运行验证", "本地命令：moon run cmd/main -- keygen 生成密钥对；moon run examples/basic_audit 跑通端到端审计；moon run cmd/main -- audit pkg ver \"src/main.mbt:fn main {}\"  产出包含风险评分与 JSON 报告的标准输出。"),
    ]
    for title, text in sections2:
        flow.append(Paragraph(title, h2))
        flow.append(Paragraph(text, body))

    flow.append(Spacer(1, 6))
    flow.append(Paragraph(
        "本申报书内容限定在一页 PDF（按章程要求），完整技术细节见 "
        "<b>README.zh.md</b>、<b>docs/API.zh.md</b> 与 <b>PROJECT_PROPOSAL.md</b>。",
        body,
    ))

    doc.build(flow)
    size = os.path.getsize(pdf_path)
    print(f"Wrote {pdf_path} ({size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())