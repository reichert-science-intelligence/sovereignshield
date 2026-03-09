# Phase 2 → Hardening Sprint Checklist

Run this checklist after every feature phase ships, before starting the next phase.

## 1. Build & Dependencies

- [ ] `pyproject.toml` exists and is authoritative (not requirements.txt alone)
- [ ] Dependencies pinned with versions
- [ ] `pip install -e .` or equivalent works from repo root

## 2. Code Quality

- [ ] All public functions have type hints
- [ ] Business logic separated from Shiny reactive logic
- [ ] No relative import hacks — package structure is correct

## 3. Testing

- [ ] Minimum 3 unit tests per new module
- [ ] Every shipped module has at least one unit test
- [ ] Tests run clean: `pytest` or project test command

## 4. Documentation

- [ ] `ARCHITECTURE.md` updated for any structural changes
- [ ] Supabase schema changes reflected in `ARCHITECTURE.md` (never merge schema changes without this)
- [ ] README current for setup and run instructions

## 5. Pre-Phase Gate

- [ ] No structural refactoring left embedded in the feature branch — defer to hardening
- [ ] All new modules have tests before phase sign-off
- [ ] Ready to start next feature phase

---

**Reference:** `.cursorrules` in repo root — Engineering Hardening Standards
