"""Official NAF signal distribution list helpers.

The lists are based on the bundled "CURRENT NOMENCLATURS OF NAF UNITS – 2024" document.
They power the signal recipient builder: list selection, ALL NAF units, individual unit
addition, and LESS/exclusion routing.
"""
from __future__ import annotations

import re
from collections import OrderedDict

NAF_DISTRIBUTION_LISTS = OrderedDict({
    "LIST A": [
        "PASO-CAS", "COPP", "CTOP", "CAI", "CACE", "CLOG", "CCIS", "COA", "COSE", "AIR SEC", "CAB", "CMS", "CT&I", "CCMR",
        "AILS", "PIMT COORD", "NAFOMB", "DOPOL", "DOPLANS", "DOMA", "DOO", "DPSO", "DOT", "DOREGT", "DATS", "D INT",
        "DCIS", "DISR", "DTECH INT", "DAE", "DOARM", "DALCM", "DAQA", "DPROD", "DMSM", "DOL", "DPROC", "DOW", "DOS",
        "DLA", "DCATS", "DCOMMS", "DIT", "D RADAR", "D SPACE TECH", "DOA", "DVA", "DAP", "DLS", "DOPRI", "DOEDN", "DSPE",
        "DC-RC", "DC-P", "DOIA", "D MUSIC", "DOEVAL", "DOSAF", "DAW&C", "DOM", "DPM", "DRRR", "DOF", "DOBUD", "DOACCTS",
        "DOINSP", "DCS", "DOMS", "DPHHS", "DNS", "DOTS", "DDS", "DMSS", "DNT", "DR&D", "Dir Doc Dev & Lesson Learnt",
        "Dir Coord & Coop", "Dir Enabling Op", "Dir Human Rights & Gender Affairs",
    ],
    "LIST A-1": [
        "PASO-CAS", "COPP", "CTOP", "CAI", "CACE", "CLOG", "CCIS", "COA", "COSE", "AIR SEC", "CAB", "CMS", "CT&I", "CCMR",
    ],
    "LIST B": [
        "HQ TAC", "HQ SOC", "HQ MC", "HQ ATC", "HQ GTC", "HQ LC", "011 PAF ABUJA", "013 QRF MINNA", "015 SIG IKEJA",
        "041 CIS DEPOT", "051 PMG IKEJA", "053 HQ NAF CAMP", "055 HQ NAF CAMP", "057 PIG IKEJA", "061 AMC KADUNA",
        "063 NAFH ABUJA", "065 NAFH ABUJA", "081 PAG IKEJA", "AFIT KADUNA", "AFRDI OSOGBO", "NAFILGC ABUJA", "NAFIL",
        "NAFILHCC ABUJA", "NAFIL PROP ABUJA", "AFWC MAKURDI", "AWC ABUJA", "NADC LAGOS", "NAFWC ABUJA", "AETSL ABUJA",
        "NAFRC KADUNA", "NAFSMSAM KADUNA", "NAFCONS KADUNA", "IAPS ABUJA",
    ],
    "LIST B-1": ["HQ TAC", "HQ SOC", "HQ MC", "HQ ATC", "HQ GTC", "HQ LC"],
    "LIST C": [
        "101 ADG MAKURDI", "103 STG YOLA", "105 CG MAIDUGURI", "107 AMG BENIN", "109 CRG GOMBE", "115 SOG PORT HARCOURT",
        "119 CG SOKOTO", "120 FPG MAKURDI", "131 ENGR GP MAKURDI", "141 COMMS GP MAKURDI", "151 BSG MAKURDI", "153 BSG YOLA",
        "161 NAFH MAKURDI", "163 NAFH YOLA", "HEL DET MAIDUGURI", "NAFRH PORT HARCOURT", "201 CG BAUCHI", "203 ISR GP YOLA",
        "205 SOG EKITI", "207 QRG GUSAU", "211 QRG OWERRI", "212 FPG BAUCHI", "213 FOB KATSINA", "231 HOD BAUCHI",
        "241 COMMS GP BAUCHI", "251 BSG BAUCHI", "261 NAFRH BAUCHI", "263 NAFRH DAURA", "301 HAG IKEJA", "303 CG ILORIN",
        "305 SMG CALABAR", "307 EAG ABUJA", "341 COMMS GP ILORIN", "401 FTS KADUNA", "403 FTS KANO", "405 HCTG ENUGU",
        "407 ACTG KAINJI", "409 IHFS ENUGU", "410 CFS KATSINA", "413 FPG KADUNA", "431 ENGR GP KADUNA", "433 ENGR GP KAINJI",
        "441 COMMS GP KADUNA", "453 BSG KADUNA", "455 BSG KANO", "461 NAFH KADUNA", "465 NAFH KANO", "ATSTC KADUNA",
        "NAFIS IPETU-IJESHA", "NAFSAINT MAKURDI", "NAF CAOCC KADUNA", "541 COMMS GP ENUGU", "551 NAF STN JOS", "553 BSG ENUGU",
        "561 NAFH ENUGU", "563 NAFH JOS", "APTC KERANG", "MTC KADUNA", "NAFIAM KADUNA", "RTC KADUNA", "NAFSFA IBADAN",
        "613 FPG LAGOS", "631 ACMD IKEJA", "633 CAD MAKURDI", "635 ASG KAINJI", "641 COMMS GP IKEJA", "643 ESD IKEJA",
        "651 BSG IKEJA", "653 NAF STN BADAGRY", "655 NAF STN IBADAN", "661 NAFH IKEJA", "663 NAF M&C HOSP BADAGRY",
    ],
    "LIST D": ["DAS", "HQ DICON", "NIPSS KURU", "NEMA"],
    "LIST E": [
        "DHQ", "AHQ", "NHQ", "DIA", "DSA", "ONSA", "AFCSC", "NDA", "NDC", "NAFRC", "MPB", "AFSH KANO", "DRDB",
        "OP DELTA SAFE", "OP HADIN KAI", "OP SAFE HAVEN", "OP WHIRLSTROKE", "OP AWASTE", "OP UDOKA", "OP FASAN YAMMA",
    ],
    "INDEPENDENT WINGS": [
        "1201 FPW YOLA", "1202 FPW MAIDUGURI", "2071 FPW DAURA", "2073 FPW KATSINA", "2075 FPW SOKOTO", "4131 FPW KAINJI",
        "4135 FPW B/GWARI", "6041 FPW OSOGBO", "6043 FPW IBADAN", "6045 FPW BADAGRY", "6047 FPW ILORIN", "6141 FPW IPETU-IJESA",
        "QRW DAURA", "156 FOB MONGUNO", "157 FOB MUBI", "215 FOB FUNTUA", "217 FOB AZARE", "205 RW IKEJA", "RTC ANNEX BAUCHI",
        "1 AMC MAKURDI", "2 AMC KANO", "3 AMC PORT HARCOURT", "1 ASC KAINJI", "2 ASC ENUGU", "3 ASC MAIDUGURI", "65 BSW OSOGBO",
        "25 FPW KERANG", "BSW ABUJA", "21 QRW AGATU", "22 QRW DOMA", "23 QRW NGUROJE", "214 FOB WARRI", "FOB OGOJA",
        "35 BSW YENAGOA", "5531 FPW ENUGU",
    ],
})

LIST_DESCRIPTIONS = {
    "LIST A": "Air Staff / AHQ directorates",
    "LIST A-1": "Principal command appointments",
    "LIST B": "Direct Reporting Units and commands",
    "LIST B-1": "Command headquarters",
    "LIST C": "NAF operational, training, logistics and medical units",
    "LIST D": "Defence / government liaison bodies",
    "LIST E": "External military/security addressees and operations",
    "INDEPENDENT WINGS": "Independent wings under parent groups",
}


def normalize_unit_name(name: str) -> str:
    value = (name or "").upper()
    value = value.replace("–", "-").replace("—", "-")
    value = re.sub(r"[^A-Z0-9]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def unit_code_from_name(name: str) -> str:
    value = normalize_unit_name(name).replace(" ", "-")
    return re.sub(r"-+", "-", value).strip("-")[:40] or "UNIT"


def all_official_unit_names() -> list[str]:
    seen = OrderedDict()
    for units in NAF_DISTRIBUTION_LISTS.values():
        for name in units:
            key = normalize_unit_name(name)
            if key and key not in seen:
                seen[key] = name
    return list(seen.values())


def distribution_payload(units) -> dict:
    """Return JSON-ready distribution lists mapped to actual Unit IDs.

    Matching is tolerant: exact official name, code, and compressed-name comparisons.
    """
    by_norm = {}
    for u in units:
        candidates = {normalize_unit_name(u.name), normalize_unit_name(u.code)}
        # Also match shortened old seed entries like "641 COMS GP" against official "641 COMMS GP IKEJA" by prefix.
        for c in list(candidates):
            if c:
                by_norm.setdefault(c, u)
    def match(name):
        n = normalize_unit_name(name)
        if n in by_norm:
            return by_norm[n]
        # Prefix fallback for legacy seed names without location.
        for key, unit in by_norm.items():
            if key and (n.startswith(key + " ") or key.startswith(n + " ")):
                return unit
        return None
    lists = []
    for list_name, names in NAF_DISTRIBUTION_LISTS.items():
        mapped = []
        missing = []
        seen_ids = set()
        for name in names:
            u = match(name)
            if u and u.id not in seen_ids:
                mapped.append({"id": u.id, "name": u.name, "code": u.code, "official": name})
                seen_ids.add(u.id)
            else:
                missing.append(name)
        lists.append({
            "name": list_name,
            "description": LIST_DESCRIPTIONS.get(list_name, "Official NAF distribution list"),
            "count": len(mapped),
            "units": mapped,
            "missing": missing,
        })
    all_ids = []
    seen = set()
    for row in lists:
        for u in row["units"]:
            if u["id"] not in seen:
                all_ids.append(u["id"]); seen.add(u["id"])
    return {"lists": lists, "allUnitIds": all_ids}


def resolve_distribution_unit_ids(units, list_names=None, include_all=False) -> set[int]:
    payload = distribution_payload(units)
    selected = {str(x).strip().upper() for x in (list_names or []) if str(x).strip()}
    ids = set(payload["allUnitIds"] if include_all else [])
    for row in payload["lists"]:
        if row["name"].upper() in selected:
            ids.update(int(u["id"]) for u in row["units"])
    return ids


def build_route_display(list_names=None, include_all=False, added_units=None, excluded_units=None) -> str:
    parts = []
    if include_all:
        parts.append("ALL NAF UNITS")
    parts.extend([str(x).strip().upper() for x in (list_names or []) if str(x).strip()])
    added = [getattr(u, "code", None) or getattr(u, "name", "") for u in (added_units or [])]
    if added:
        parts.append("UNITS: " + ", ".join(added))
    excluded = [getattr(u, "code", None) or getattr(u, "name", "") for u in (excluded_units or [])]
    if excluded:
        parts.append("LESS " + ", ".join(excluded))
    return "; ".join(parts)
