# exhume_indexer

The `exhume_indexer` documentation is maintained at [forensicxlab.com](https://www.forensicxlab.com/docs/exhume_indexer/getting-started).

Indexing continues past unreadable file records, directory subtrees and NTFS index blocks. Validated entries are indexed; skipped entries are recorded as diagnostics rather than placeholder files. Source-opening, root/bootstrap and database failures still stop the run.

Use `--json-report` to print the final run summary. The CLI returns `0` for complete coverage, `2` for completion with issues, `1` for a fatal error or resource limit, and `130` for cancellation. These checks always apply; there is no strict-mode option.

SQLite stores attempt history in `index_runs`, diagnostics in `index_issues`, and the currently published inventory's run in `index_inventory`. Counts describe observed gaps; they cannot estimate how many files an unreadable subtree or block concealed.

```sql
SELECT r.id, r.status, r.report_json
FROM index_inventory i JOIN index_runs r ON r.id = i.run_id;

SELECT phase, path, record_id, code, action, message
FROM index_issues WHERE run_id = ? ORDER BY id;
```

Reuse `--partition-id` when retrying an existing partition. Inventory replacement is atomic, unchanged path/record identities retain their file IDs, and a failed or cancelled discovery preserves the previous inventory. Replacing an inventory clears its derived signatures, artefacts and timeline rows so they can be rebuilt. Analysis cancellation can retain the published file inventory while leaving its analysis incomplete.

Library callers can use `Filesystem::walk_fs` and `index_filesystem_with_report` (or the partition/folder report entry points). Wrap subsequent analysis passes in `report::run_reported_phase` to persist typed per-file parser/signature failures and aggregate the final status. The walker accepts `WalkOptions` and a fallible `WalkEvent` callback; `WalkItem` and `walk_fs_with_report` have been removed. Fatal `WalkError` values include the observed coverage and distinguish source failures from callback failures. Warnings use the `log` facade; log filtering never changes persisted diagnostics.
