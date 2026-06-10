from __future__ import annotations
from typing import Optional, Set
from .models import Unit

def is_in_subtree(child_unit: Optional[Unit], target_unit_id: Optional[int]) -> bool:
    """True if child_unit is the target unit or a descendant of it."""
    if child_unit is None or target_unit_id is None:
        return False
    u = child_unit
    while u is not None:
        if u.id == int(target_unit_id):
            return True
        u = u.parent
    return False

def ancestry_ids(unit: Optional[Unit]) -> list[int]:
    if unit is None:
        return []
    ids=[]
    p=unit.parent
    while p is not None:
        ids.append(p.id)
        p=p.parent
    return ids

def visible_unit_ids_for_user(unit: Optional[Unit]) -> Set[int]:
    """Unit IDs a user can naturally see in navigation: own unit + ancestors."""
    if unit is None:
        return set()
    return set([unit.id] + ancestry_ids(unit))
