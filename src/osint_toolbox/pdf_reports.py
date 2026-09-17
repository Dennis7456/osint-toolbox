from __future__ import annotations

import html
import json
from io import BytesIO
from pathlib import Path
from typing import Any

from .case import append_ledger
from .exports import _snapshot, build_redacted_snapshot
from .util import ensure_case, sha256_bytes, write_bytes


def _text(value: Any, limit: int = 1800) -> str:
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    elif value is None:
        rendered = ""
    else:
        rendered = str(value)
    rendered = " ".join(rendered.split())
    if len(rendered) > limit:
        rendered = rendered[: limit - 24].rstrip() + " ... [PDF truncated]"
    return rendered or "-"


def _build_pdf(snapshot: dict[str, Any]) -> bytes:
    try:
        import reportlab
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.pdfgen.canvas import Canvas
        from reportlab.platypus import LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise ValueError(
            "PDF reporting requires ReportLab; install osint-toolbox[pdf] or the reportlab package"
        ) from exc

    font_dir = Path(reportlab.__file__).resolve().parent / "fonts"
    try:
        pdfmetrics.getFont("OSINTVera")
    except KeyError:
        pdfmetrics.registerFont(TTFont("OSINTVera", str(font_dir / "Vera.ttf")))
        pdfmetrics.registerFont(TTFont("OSINTVera-Bold", str(font_dir / "VeraBd.ttf")))

    navy = colors.HexColor("#17324D")
    teal = colors.HexColor("#167D88")
    pale = colors.HexColor("#EAF2F4")
    lighter = colors.HexColor("#F7F9FA")
    line = colors.HexColor("#B8C7CF")
    muted = colors.HexColor("#4C5C66")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "OsintTitle",
        parent=styles["Title"],
        fontName="OSINTVera-Bold",
        fontSize=19,
        leading=23,
        textColor=navy,
        spaceAfter=8,
    )
    subtitle_style = ParagraphStyle(
        "OsintSubtitle",
        parent=styles["Normal"],
        fontName="OSINTVera",
        fontSize=8.5,
        leading=12,
        textColor=muted,
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "OsintHeading",
        parent=styles["Heading2"],
        fontName="OSINTVera-Bold",
        fontSize=12,
        leading=15,
        textColor=navy,
        spaceBefore=11,
        spaceAfter=6,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "OsintBody",
        parent=styles["BodyText"],
        fontName="OSINTVera",
        fontSize=8.2,
        leading=11,
        textColor=colors.HexColor("#202A30"),
    )
    small_style = ParagraphStyle(
        "OsintSmall",
        parent=body_style,
        fontSize=6.8,
        leading=8.5,
        wordWrap="CJK",
    )
    label_style = ParagraphStyle(
        "OsintLabel",
        parent=small_style,
        fontName="OSINTVera-Bold",
        textColor=navy,
    )
    header_style = ParagraphStyle(
        "OsintTableHeader",
        parent=small_style,
        fontName="OSINTVera-Bold",
        textColor=colors.white,
    )
    notice_style = ParagraphStyle(
        "OsintNotice",
        parent=body_style,
        fontName="OSINTVera-Bold",
        textColor=colors.HexColor("#8A3B12"),
        borderColor=colors.HexColor("#D29A73"),
        borderWidth=0.7,
        borderPadding=7,
        backColor=colors.HexColor("#FFF5ED"),
        spaceAfter=10,
    )

    def paragraph(value: Any, style: Any = small_style, limit: int = 1800) -> Any:
        return Paragraph(html.escape(_text(value, limit)), style)

    def section(story: list[Any], title: str) -> None:
        story.append(Paragraph(html.escape(title), heading_style))

    def table(story: list[Any], headers: list[str], rows: list[list[Any]], widths: list[float]) -> None:
        if not rows:
            story.append(Paragraph("No records.", body_style))
            return
        data = [[paragraph(item, header_style, 200) for item in headers]]
        data.extend([[paragraph(item) for item in row] for row in rows])
        report_table = LongTable(data, colWidths=widths, repeatRows=1, hAlign="LEFT", splitByRow=1)
        report_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "OSINTVera-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.35, line),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, lighter]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.extend([report_table, Spacer(1, 5)])

    case = snapshot["case"]
    legal_hold = case.get("legal_hold") if isinstance(case.get("legal_hold"), dict) else {}
    datasets = snapshot["datasets"]
    integrity = snapshot.get("integrity", {})
    redaction = snapshot.get("redaction")
    case_id = _text(case.get("case_id"), 120)
    classification = "REDACTED DERIVATIVE" if redaction else _text(case.get("sensitivity", "UNCLASSIFIED"), 80).upper()

    class InvariantCanvas(Canvas):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["invariant"] = 1
            kwargs["pageCompression"] = 1
            super().__init__(*args, **kwargs)

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=_text(case.get("title"), 200),
        author="OSINT Toolbox",
        subject=f"Evidence-first case report {case_id}",
    )

    def page_frame(canvas: Any, doc: Any) -> None:
        width, height = A4
        canvas.saveState()
        canvas.setTitle(_text(case.get("title"), 200))
        canvas.setAuthor("OSINT Toolbox")
        canvas.setSubject(f"Evidence-first case report {case_id}")
        canvas.setFont("OSINTVera-Bold", 7)
        canvas.setFillColor(navy)
        canvas.drawString(18 * mm, height - 11 * mm, f"OSINT TOOLBOX | {case_id}")
        canvas.setFillColor(teal)
        canvas.drawRightString(width - 18 * mm, height - 11 * mm, classification)
        canvas.setStrokeColor(line)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, height - 13 * mm, width - 18 * mm, height - 13 * mm)
        canvas.line(18 * mm, 12 * mm, width - 18 * mm, 12 * mm)
        canvas.setFont("OSINTVera", 6.5)
        canvas.setFillColor(muted)
        canvas.drawString(18 * mm, 8 * mm, "Source-aware analytic report - verify against the controlled case")
        canvas.drawRightString(width - 18 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story: list[Any] = [
        Paragraph(html.escape(_text(case.get("title"), 500)), title_style),
        Paragraph(
            "Evidence-first structured report. Observations, candidate leads, assessed claims, and unknowns remain distinct.",
            subtitle_style,
        ),
    ]
    if redaction:
        story.append(Paragraph(
            html.escape(
                f"REDACTED DERIVATIVE - policy SHA-256 {redaction.get('policy_sha256', '')}. "
                f"{redaction.get('warning', '')}"
            ),
            notice_style,
        ))
    if legal_hold.get("active"):
        story.append(Paragraph(
            html.escape(
                f"LEGAL HOLD ACTIVE - {legal_hold.get('hold_id', '')}. "
                f"Reason: {legal_hold.get('reason', '')}. Authority: {legal_hold.get('authority', '')}."
            ),
            notice_style,
        ))
    if not integrity.get("valid", False):
        story.append(Paragraph(
            "INTEGRITY CHECK FAILED - do not rely on this report until the listed issues are resolved.",
            notice_style,
        ))

    metadata_rows = [
        [paragraph("Case ID", label_style), paragraph(case_id, body_style), paragraph("Status", label_style), paragraph(case.get("status"), body_style)],
        [paragraph("Target type", label_style), paragraph(case.get("target_type"), body_style), paragraph("Target", label_style), paragraph(case.get("target"), body_style)],
        [paragraph("Purpose", label_style), paragraph(case.get("purpose"), body_style), paragraph("Authority", label_style), paragraph(case.get("authority"), body_style)],
        [paragraph("Sensitivity", label_style), paragraph(case.get("sensitivity"), body_style), paragraph("Collection tier", label_style), paragraph(case.get("collection_tier"), body_style)],
        [paragraph("Jurisdictions", label_style), paragraph(case.get("jurisdictions"), body_style), paragraph("Retention until", label_style), paragraph(case.get("retention_until"), body_style)],
        [paragraph("Legal hold", label_style), paragraph("ACTIVE" if legal_hold.get("active") else "Not active", body_style), paragraph("Hold ID", label_style), paragraph(legal_hold.get("hold_id"), body_style)],
        [paragraph("Owner", label_style), paragraph(case.get("owner"), body_style), paragraph("Reviewers", label_style), paragraph(case.get("reviewers"), body_style)],
        [paragraph("Created UTC", label_style), paragraph(case.get("created_at_utc"), body_style), paragraph("Integrity", label_style), paragraph("PASS" if integrity.get("valid") else "FAIL", body_style)],
    ]
    metadata = Table(metadata_rows, colWidths=[27 * mm, 48 * mm, 27 * mm, 57 * mm], hAlign="LEFT")
    metadata.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), pale),
        ("BACKGROUND", (2, 0), (2, -1), pale),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, line),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.extend([metadata, Spacer(1, 8)])

    section(story, "Assessed claims")
    table(story, ["ID", "Assessment", "Claim", "Source IDs"], [
        [row.get("claim_id"), f"{row.get('confidence')} / {row.get('status')}",
         f"{_text(row.get('statement'), 2600)} Notes: {_text(row.get('notes'), 700)}", row.get("source_ids")]
        for row in datasets.get("claims", [])
    ], [24 * mm, 27 * mm, 78 * mm, 30 * mm])

    section(story, "Observation register")
    table(story, ["ID", "Kind / status", "Value", "Provenance"], [
        [row.get("observation_id"), f"{row.get('kind')} / {row.get('status')}", row.get("value"),
         f"Source: {row.get('source_id')} Artifact: {row.get('artifact_id')} Observed: {row.get('observed_at')}"]
        for row in datasets.get("observations", [])
    ], [24 * mm, 34 * mm, 72 * mm, 29 * mm])

    section(story, "Entity and relationship register")
    table(story, ["ID", "Type", "Label / role", "Evidence"], [
        [row.get("entity_id"), row.get("entity_type"), f"{row.get('label')} / {row.get('role')}",
         f"Confidence: {row.get('confidence')} Sources: {_text(row.get('source_ids'))}"]
        for row in datasets.get("entities", [])
    ], [24 * mm, 30 * mm, 68 * mm, 37 * mm])
    table(story, ["ID", "Relationship", "Evidence"], [
        [row.get("relationship_id"),
         f"{row.get('from_entity_id')} --{row.get('relationship_type')}--> {row.get('to_entity_id')}",
         f"{row.get('evidence_kind')} / {row.get('confidence')} / Sources: {_text(row.get('source_ids'))}"]
        for row in datasets.get("relationships", [])
    ], [25 * mm, 88 * mm, 46 * mm])

    section(story, "Timeline")
    table(story, ["ID", "Time", "Event", "Source IDs"], [
        [row.get("event_id"), f"{row.get('start_at_utc') or row.get('start_at')} to {row.get('end_at_utc') or row.get('end_at')}",
         f"{row.get('event_type')}: {row.get('label')} ({row.get('confidence')})", row.get("source_ids")]
        for row in sorted(datasets.get("events", []), key=lambda item: item.get("start_at_utc", item.get("start_at", "")))
    ], [24 * mm, 39 * mm, 66 * mm, 30 * mm])

    story.append(PageBreak())
    section(story, "Source register")
    table(story, ["ID", "Assessment", "Source", "URL"], [
        [row.get("source_id"), f"{row.get('reliability')} / {row.get('credibility')}",
         f"{row.get('title')} ({row.get('topic')}) Accessed: {row.get('accessed_at_utc')}", row.get("url")]
        for row in datasets.get("sources", [])
    ], [24 * mm, 27 * mm, 70 * mm, 38 * mm])

    section(story, "Artifact register")
    table(story, ["ID", "File", "Details", "SHA-256"], [
        [row.get("artifact_id"), row.get("stored_path"),
         f"{row.get('mime_type')} / {row.get('size_bytes')} bytes / {row.get('topic')}", row.get("sha256")]
        for row in datasets.get("artifacts", [])
    ], [24 * mm, 52 * mm, 45 * mm, 38 * mm])

    section(story, "Limitations and method")
    issues = integrity.get("issues", [])
    limitations = (
        "Integrity issues: " + "; ".join(_text(issue, 500) for issue in issues)
        if issues
        else "No structural integrity issue was detected at rendering time. Document collection gaps, source limitations, alternative explanations, and reviewer decisions separately."
    )
    story.extend([
        Paragraph(html.escape(limitations), body_style),
        Spacer(1, 6),
        Paragraph(
            "Collection is limited to the recorded authority and purpose. Source observations are separated from analytic claims. "
            "Candidate usernames and inferred relationships are not identity proof. Artifact hashes and normalized provenance remain in the controlled case. "
            "This PDF does not embed source files and may truncate unusually long fields; use the verified JSON export and evidence bundle for complete machine-readable records.",
            body_style,
        ),
    ])

    document.build(story, onFirstPage=page_frame, onLaterPages=page_frame, canvasmaker=InvariantCanvas)
    return buffer.getvalue()


def render_pdf_report(
    case: str | Path,
    output: str | Path | None = None,
    policy_path: str | Path | None = None,
) -> tuple[Path, str]:
    case_dir = ensure_case(case)
    if policy_path:
        snapshot, policy_hash = build_redacted_snapshot(case_dir, policy_path)
    else:
        snapshot = _snapshot(case_dir)
        policy_hash = ""
    pdf_bytes = _build_pdf(snapshot)
    default_name = "report-redacted.pdf" if policy_path else "report.pdf"
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / default_name
    write_bytes(destination, pdf_bytes)
    digest = sha256_bytes(pdf_bytes)
    payload: dict[str, Any] = {
        "format": "redacted-pdf" if policy_path else "pdf",
        "path": str(destination),
        "sha256": digest,
        "reproducible": True,
    }
    if policy_hash:
        payload["policy_sha256"] = policy_hash
    append_ledger(case_dir, "report.rendered", payload, "system")
    return destination, digest
