# Spec Fixtures

Test fixtures for validating JSON schemas. These files must validate against their
corresponding schemas in `docs/schema/`.

## Files

### Current (Checkpoint Chain Architecture)

| Fixture | Schema | Description |
|---------|--------|-------------|
| `evidence-packet-v1.example.json` | `evidence-packet-v1.schema.json` | Realistic example with 5 checkpoints, keystroke evidence, declaration |
| `forensic-profile-v1.json` | `forensic-profile-v1.schema.json` | Minimal forensic profile |

### Legacy (MMR Architecture - Deprecated)

| Fixture | Schema | Status |
|---------|--------|--------|
| `witness-proof-v1.json` | `witness-proof-v1.schema.json` | **Deprecated** - MMR format not used in current exports |

## CI Integration

Run schema validation:
```bash
# Requires ajv-cli: npm install -g ajv-cli
ajv validate -s ../schema/evidence-packet-v1.schema.json -d evidence-packet-v1.example.json
ajv validate -s ../schema/forensic-profile-v1.schema.json -d forensic-profile-v1.json
```

## Notes

- The `witness-proof-v1.json` fixture uses the deprecated MMR-based format
- New evidence exports use `evidence-packet-v1.schema.json` (checkpoint chain format)
- See `PROTOCOL-UPDATE-RECOMMENDATIONS.md` for migration details
