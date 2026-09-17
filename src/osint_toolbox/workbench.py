"""Append-only analyst decisions and a self-contained, offline review view."""
from __future__ import annotations

import html
import json
import os
from pathlib import Path
from typing import Any

from .case import _append_record, _known_ids, _require_ids, verify_case
from .util import ensure_case, new_id, read_json, read_jsonl, utc_now


def active_resolution_groups(entities: list[dict[str, Any]], decisions: list[dict[str, Any]]) -> list[list[str]]:
    """Rebuild components from active merge decisions; never rewrite source entities."""
    active = {row["resolution_id"]: row for row in decisions if row["action"] == "merge"}
    for row in decisions:
        if row["action"] == "split":
            active.pop(row["reverses_id"], None)
    parent = {row["entity_id"]: row["entity_id"] for row in entities}

    def root(identifier: str) -> str:
        while parent[identifier] != identifier:
            identifier = parent[identifier]
        return identifier

    for row in active.values():
        left, right = row["entity_ids"]
        if left in parent and right in parent:
            parent[root(right)] = root(left)
    groups: dict[str, list[str]] = {}
    for identifier in parent:
        groups.setdefault(root(identifier), []).append(identifier)
    return sorted((sorted(members) for members in groups.values()), key=lambda group: group[0])


def record_resolution(
    case: str | Path, action: str, entity_ids: list[str], features: list[dict[str, Any]],
    source_ids: list[str], reason: str, reverses_id: str = "", analyst: str = "operator",
) -> dict[str, Any]:
    case_dir = ensure_case(case)
    if action not in {"merge", "split"} or len(entity_ids) != 2 or len(set(entity_ids)) != 2:
        raise ValueError("Resolution requires merge or split and two distinct entity IDs")
    entity_ids = sorted(entity_ids)
    _require_ids(entity_ids, _known_ids(case_dir, "entities.jsonl", "entity_id"), "entity ID")
    known_sources = _known_ids(case_dir, "sources.jsonl", "source_id")
    _require_ids(source_ids, known_sources, "source ID")
    if not reason.strip():
        raise ValueError("A resolution reason is required")
    if action == "merge":
        if reverses_id or not features:
            raise ValueError("Merge requires evidence features and cannot reverse a decision")
        for feature in features:
            if not isinstance(feature, dict) or not feature.get("description", "").strip():
                raise ValueError("Each merge feature needs a description")
            _require_ids(feature.get("source_ids", []), known_sources, "feature source ID")
            if not set(feature["source_ids"]).issubset(source_ids):
                raise ValueError("Feature sources must be included in resolution source IDs")
    else:
        if not reverses_id or features:
            raise ValueError("Split requires a merge ID to reverse and no new features")
        decisions = read_jsonl(case_dir / "resolutions.jsonl")
        merges = {row["resolution_id"]: row for row in decisions if row["action"] == "merge"}
        reversed_ids = {row["reverses_id"] for row in decisions if row["action"] == "split"}
        if reverses_id not in merges or reverses_id in reversed_ids or merges[reverses_id]["entity_ids"] != entity_ids:
            raise ValueError("Split must reverse an active merge of the same entities")
    record = {
        "resolution_id": new_id("RES"), "action": action, "entity_ids": entity_ids,
        "features": features, "source_ids": sorted(set(source_ids)), "reason": reason.strip(),
        "reverses_id": reverses_id, "analyst": analyst.strip() or "operator", "created_at_utc": utc_now(),
    }
    return _append_record(case_dir, "resolutions.jsonl", "resolution.recorded", record, record["analyst"])


def record_worksheet(case: str | Path, data: dict[str, Any], analyst: str = "operator") -> dict[str, Any]:
    case_dir = ensure_case(case)
    if not isinstance(data, dict):
        raise ValueError("Worksheet must be a JSON object")
    permitted = {"kind", "title", "subject_artifact_id", "source_ids", "artifact_ids", "clues", "candidates", "leads", "assessment"}
    if set(data) - permitted:
        raise ValueError("Unknown worksheet fields: " + ", ".join(sorted(set(data) - permitted)))
    kind = data.get("kind")
    if kind not in {"geolocation", "media-provenance"}:
        raise ValueError("Worksheet kind must be geolocation or media-provenance")
    if not isinstance(data.get("title"), str) or not data["title"].strip():
        raise ValueError("Worksheet title is required")
    known_sources = _known_ids(case_dir, "sources.jsonl", "source_id")
    known_artifacts = _known_ids(case_dir, "artifacts.jsonl", "artifact_id")
    sources = data.get("source_ids", [])
    _require_ids(sources, known_sources, "source ID")
    artifacts = data.get("artifact_ids", [])
    _require_ids(artifacts, known_artifacts, "artifact ID", allow_empty=True)
    subject = data.get("subject_artifact_id", "")
    if subject:
        _require_ids([subject], known_artifacts, "subject artifact ID")
        if subject not in artifacts:
            raise ValueError("Subject artifact must be included in artifact_ids")
    clues = data.get("clues", [])
    candidates = data.get("candidates", [])
    leads = data.get("leads", [])
    if kind == "geolocation" and (not clues or not candidates or leads):
        raise ValueError("Geolocation requires clues and candidates, not media leads")
    if kind == "media-provenance" and (not leads or clues or candidates):
        raise ValueError("Media provenance requires leads, not location clues or candidates")
    for feature in clues:
        _validate_feature(feature, sources, known_sources)
    for lead in leads:
        if not isinstance(lead, dict) or set(lead) != {"lead_kind", "description", "url", "observed_at", "source_ids", "notes"}:
            raise ValueError("Media lead needs kind, description, URL, observed_at, source_ids and notes")
        if lead["lead_kind"] not in {"reverse-search", "earliest-appearance", "other"} or not isinstance(lead["url"], str) or not lead["url"].startswith(("https://", "http://")):
            raise ValueError("Media lead needs a known kind and HTTP(S) URL")
        _validate_feature({"description": lead["description"], "source_ids": lead["source_ids"]}, sources, known_sources)
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != {"label", "source_ids", "matched_features", "mismatched_features", "map_artifact_ids"}:
            raise ValueError("Candidate needs label, sources, matched/mismatched features and map artifact IDs")
        if not isinstance(candidate["label"], str) or not candidate["label"].strip():
            raise ValueError("Candidate label is required")
        _require_ids(candidate["source_ids"], known_sources, "candidate source ID")
        if not set(candidate["source_ids"]).issubset(sources):
            raise ValueError("Candidate sources must be included in worksheet source IDs")
        _require_ids(candidate["map_artifact_ids"], known_artifacts, "map artifact ID", allow_empty=True)
        if not set(candidate["map_artifact_ids"]).issubset(artifacts):
            raise ValueError("Map artifacts must be included in worksheet artifact IDs")
        for feature in [*candidate["matched_features"], *candidate["mismatched_features"]]:
            _validate_feature(feature, sources, known_sources)
    record = {
        "worksheet_id": new_id("WSH"), "kind": kind, "title": data["title"].strip(),
        "subject_artifact_id": subject, "source_ids": sources, "artifact_ids": artifacts,
        "clues": clues, "candidates": candidates, "leads": leads,
        "assessment": data.get("assessment", ""), "analyst": analyst.strip() or "operator",
        "created_at_utc": utc_now(),
    }
    return _append_record(case_dir, "worksheets.jsonl", "worksheet.recorded", record, record["analyst"])


def _validate_feature(feature: Any, sources: list[str], known: set[str]) -> None:
    if not isinstance(feature, dict) or set(feature) != {"description", "source_ids"}:
        raise ValueError("Clues, leads and features require description and source_ids")
    if not isinstance(feature["description"], str) or not feature["description"].strip():
        raise ValueError("Feature description is required")
    _require_ids(feature["source_ids"], known, "feature source ID")
    if not set(feature["source_ids"]).issubset(sources):
        raise ValueError("Feature sources must be included in worksheet source IDs")


def render_workbench(case: str | Path, output: str | Path | None = None) -> Path:
    case_dir = ensure_case(case)
    ok, issues = verify_case(case_dir)
    if not ok:
        raise ValueError("Case integrity must pass before rendering the workbench: " + "; ".join(issues))
    entities = read_jsonl(case_dir / "entities.jsonl")
    unsourced = [row["entity_id"] for row in entities if not row["source_ids"]]
    unsourced += [row["relationship_id"] for row in read_jsonl(case_dir / "relationships.jsonl") if not row["source_ids"]]
    unsourced += [row["event_id"] for row in read_jsonl(case_dir / "events.jsonl") if not row["source_ids"]]
    if unsourced:
        raise ValueError("Untraceable entities cannot appear as workbench nodes: " + ", ".join(unsourced))
    case_record = read_json(case_dir / "case.json")
    data = {
        "case": {"title": case_record["title"], "case_id": case_record["case_id"]},
        "sources": read_jsonl(case_dir / "sources.jsonl"),
        "events": read_jsonl(case_dir / "events.jsonl"),
        "entities": entities, "relationships": read_jsonl(case_dir / "relationships.jsonl"),
        "resolutions": read_jsonl(case_dir / "resolutions.jsonl"),
        "worksheets": read_jsonl(case_dir / "worksheets.jsonl"),
    }
    destination = Path(output).expanduser().resolve() if output else case_dir / "reports" / "workbench.html"
    data["groups"] = active_resolution_groups(entities, data["resolutions"])
    possible: dict[tuple[str, str], list[str]] = {}
    for entity in entities:
        key = (entity["entity_type"], " ".join(entity["label"].casefold().split()))
        possible.setdefault(key, []).append(entity["entity_id"])
    data["candidate_groups"] = [group for group in possible.values() if len(group) > 1]
    data["artifact_links"] = {row["artifact_id"]: os.path.relpath(case_dir / row["stored_path"], destination.parent) for row in read_jsonl(case_dir / "artifacts.jsonl")}
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    title = html.escape(case_record["title"])
    before, after = _PAGE.split("__DATA__", 1)
    page = before.replace("__TITLE__", title) + payload + after.replace("__TITLE__", title)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(page, encoding="utf-8")
    from .case import append_ledger
    append_ledger(case_dir, "workbench.rendered", {"path": str(destination)}, "system")
    return destination


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>__TITLE__ — OSINT workbench</title>
<style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#172633;background:#f7f9fa}header,.card{background:#fff;border:1px solid #cad5dc;border-radius:8px;padding:1rem;margin:1rem 0}nav button{padding:.6rem;margin-right:.3rem}input{padding:.6rem;width:min(95%,28rem)}small,.muted{color:#566879}a{color:#075a93}li{margin:.6rem 0}.tag{font-weight:bold;border-radius:4px;background:#e6f1fa;padding:.15rem .45rem}.inferred{background:#fff0d4}section[hidden]{display:none}</style></head>
<body><header><h1>__TITLE__</h1><p>Offline analysis workbench. Decisions are recorded by the CLI; this view is read-only. Follow source IDs to assess evidence. Inferred edges are labelled.</p><nav><button data-tab="timeline">Timeline</button><button data-tab="entities">Entities and links</button><button data-tab="worksheets">Worksheets</button><button data-tab="sources">Sources</button></nav><p><label>Filter current view <input id="filter" placeholder="Search label, ID, date, source"></label></p></header>
<main><section id="timeline"><h2>Timeline</h2><div class="items"></div></section><section id="entities" hidden><h2>Entity resolution and links</h2><p>Groups represent active, evidence-backed merges; splitting reverses the named merge without deleting either record.</p><div class="items"></div></section><section id="worksheets" hidden><h2>Geolocation and media provenance</h2><div class="items"></div></section><section id="sources" hidden><h2>Source register</h2><div class="items"></div></section></main>
<script id="case-data" type="application/json">__DATA__</script><script>
const d=JSON.parse(document.getElementById('case-data').textContent), byId=Object.fromEntries(d.sources.map(s=>[s.source_id,s]));
let tab='timeline';const input=document.getElementById('filter');
function el(tag,text,parent,cls){const node=document.createElement(tag);node.textContent=String(text??'');if(cls)node.className=cls;parent.append(node);return node}
function sources(ids,parent){const p=el('p','Sources: ',parent,'muted');for(const id of ids){const s=byId[id];const a=el('a',id+' '+(s?.title||'missing source'),p);a.href='#source-'+encodeURIComponent(id);p.append(' · ')}}
function card(parent,title,ids){const box=el('article','',parent,'card');el('h3',title,box);sources(ids,box);return box}
function draw(){const section=document.getElementById(tab),out=section.querySelector('.items');out.replaceChildren();const q=input.value.toLocaleLowerCase();const show=(obj)=>JSON.stringify(obj).toLocaleLowerCase().includes(q);
if(tab==='timeline')for(const e of [...d.events].sort((a,b)=>a.start_at_utc.localeCompare(b.start_at_utc)))if(show(e)){const b=card(out,e.start_at_utc+' '+e.label,e.source_ids);el('p',e.event_id+' · '+e.event_type+' · '+e.confidence+' confidence · '+e.start_precision+' precision',b);if(e.end_at_utc)el('p','End: '+e.end_at_utc,b);if(e.notes)el('p',e.notes,b)}
if(tab==='entities'){
 for(const group of d.candidate_groups)if(show(group)){
  const ids=[...new Set(group.flatMap(id=>d.entities.find(e=>e.entity_id===id).source_ids))];
  const b=card(out,'Candidate match: '+group.join(' / '),ids);
  el('p','Same normalized label only. Review independent features before recording a merge using resolve-entities merge.',b);
 }
 for(const group of d.groups){
  const members=group.map(id=>d.entities.find(e=>e.entity_id===id));if(!show(members))continue;
  const ids=[...new Set(members.flatMap(e=>e.source_ids))];
  const b=card(out,members.map(e=>e.label).join(' / '),ids);
  el('p',members.map(e=>e.entity_id+' ('+e.role+', '+e.confidence+')').join(' · '),b);
 }
 for(const r of d.resolutions)if(show(r)){
  const b=card(out,'Decision '+r.resolution_id+' · '+r.action.toUpperCase(),r.source_ids);
  el('p',r.entity_ids.join(' / ')+' · '+r.reason,b);
  if(r.action==='split')el('p','Reverses merge '+r.reverses_id,b);
  else {const reversed=d.resolutions.some(s=>s.action==='split'&&s.reverses_id===r.resolution_id);
   el('p',reversed?'Reversed':'Active; use resolve-entities split --reverses-id '+r.resolution_id+' to undo',b);
   for(const f of r.features)el('p','Feature: '+f.description+' ['+f.source_ids.join(', ')+']',b);
  }
 }
 for(const r of d.relationships)if(show(r)){
  const b=card(out,r.from_entity_id+' → '+r.to_entity_id,r.source_ids);
  el('p',r.relationship_id+' · '+r.relationship_type+' · '+r.evidence_kind.toUpperCase()+' · '+r.confidence+' confidence',b,r.evidence_kind==='inferred'?'tag inferred':'tag');
  if(r.notes)el('p',r.notes,b);
 }
}
if(tab==='worksheets')for(const w of d.worksheets)if(show(w)){const b=card(out,w.title+' ('+w.kind+')',w.source_ids);el('p',w.worksheet_id+' · '+w.assessment,b);for(const c of w.clues)el('p','Clue: '+c.description+' ['+c.source_ids.join(', ')+']',b);for(const c of w.candidates){el('h4','Candidate: '+c.label,b);for(const f of c.matched_features)el('p','Match: '+f.description+' ['+f.source_ids.join(', ')+']',b);for(const f of c.mismatched_features)el('p','Mismatch: '+f.description+' ['+f.source_ids.join(', ')+']',b);for(const id of c.map_artifact_ids){const a=el('a','Map snapshot '+id,b);a.href=d.artifact_links[id];b.append(' ')}}for(const lead of w.leads)el('p',lead.lead_kind+': '+lead.description+' · '+lead.url+' · '+lead.observed_at+' ['+lead.source_ids.join(', ')+']',b)}
if(tab==='sources')for(const s of d.sources)if(show(s)){const b=el('article','',out,'card');b.id='source-'+s.source_id;el('h3',s.source_id+' · '+s.title,b);const a=el('a',s.url,b);a.href=s.url;a.rel='noopener noreferrer';a.target='_blank';el('p',s.reliability+' / '+s.credibility+' · accessed '+s.accessed_at_utc,b)}}
document.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>{tab=b.dataset.tab;document.querySelectorAll('main section').forEach(s=>s.hidden=s.id!==tab);draw()}));input.addEventListener('input',draw);draw();
</script></body></html>"""
