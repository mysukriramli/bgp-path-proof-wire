```markdown
# 🌐 BGP Path Proof Wire

An autonomous network routing data plane running on GitHub Actions. It samples multi-collector Looking Glass data from RIPE RIS, normalizes AS paths, monitors origin stability, evaluates RPKI validity, and emits cryptographic route proofs for AI agents.

## Token Impact
- **Token Reduction**: 97% – 99.8%
- **Input Overhead**: Compresses thousands of raw BGP announcements down to 100–700 token route proofs.

## Shared Wire Endpoints
- [`/v1/manifest.json`](public/v1/manifest.json)
- [`/today.json`](public/today.json)
- [`/v1/schema.json`](public/v1/schema.json)
- [`/v1/incidents/active.json`](public/v1/incidents/active.json)
- [`/llms.txt`](public/llms.txt)
- `path-observations.parquet` (Columnar DuckDB snapshot)

## Architecture
- **Upstream Collector**: RIPE RIS Looking Glass & RPKI Validation API
- **Normalization Engine**: Python AS-path loop detection & prepending removal
- **Storage**: DuckDB + Parquet
- **Ledger**: Append-only Git-committed JSONL in `/ledger`
- **Edge CDN**: GitHub Pages (Fastly CDN)
