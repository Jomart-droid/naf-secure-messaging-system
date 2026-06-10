import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app, db
from app.models import Unit

CSV_PATH = Path(__file__).resolve().parents[1] / 'data' / 'naf_units_seed.csv'


def import_units(csv_path: Path = CSV_PATH) -> tuple[int, int]:
    created = 0
    updated = 0
    app = create_app()
    with app.app_context():
        with csv_path.open(newline='', encoding='utf-8') as fh:
            rows = list(csv.DictReader(fh))

        by_code = {u.code: u for u in Unit.query.all()}

        # pass 1: create or update shell records
        for row in rows:
            code = (row.get('code') or '').strip()
            if not code:
                continue
            unit = by_code.get(code)
            if unit is None:
                unit = Unit(code=code)
                db.session.add(unit)
                by_code[code] = unit
                created += 1
            else:
                updated += 1
            unit.name = (row.get('name') or code).strip()
            unit.level = (row.get('level') or 'UNIT').strip().upper()

        db.session.flush()

        # pass 2: wire parents
        for row in rows:
            code = (row.get('code') or '').strip()
            parent_code = (row.get('parent_code') or '').strip()
            unit = by_code.get(code)
            if not unit:
                continue
            parent = by_code.get(parent_code) if parent_code else None
            unit.parent = parent

        db.session.commit()
    return created, updated


if __name__ == '__main__':
    created, updated = import_units()
    print(f'Imported NAF units. Created: {created}, updated: {updated}')
