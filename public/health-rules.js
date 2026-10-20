// Rules for the Catalog Health tab. Edit this file to tune what gets flagged, then reload the page (no rebuild needed).
// Each cleanup rule is tested against the object name (the table, view or package name, without schema).
// The first rule that matches wins, so put the most specific rules first.
const CLEANUP_RULES = [
  { id: 'recycle', name: 'Oracle recycle bin', help: 'Dropped objects still in the recycle bin (BIN$...). Usually safe to purge.', test: /^BIN\$.+\$\d+$/i },
  { id: 'backup', name: 'Backup copy', help: 'Names with BKP, BAK, BACKUP or OLD, often with a date. Check whether the copy is still needed.', test: /(^|_)(BKP|BAK|BACKUP|BCKP|OLD)(_|$|\d)/i },
  { id: 'test', name: 'Test or temporary', help: 'Names with TEST, TST, TEMP, TMP, SCRATCH or DUMMY.', test: /(^|_)(TEST|TST|TEMP|TMP|SCRATCH|DUMMY|SANDBOX)(_|$|\d)/i },
  { id: 'dated', name: 'Dated copy', help: 'Names ending in a date such as _231026 or _20240115, which are often one-off copies.', test: /_(\d{6}|\d{8})$/ },
]

// Same name in several schemas: names shorter than this are ignored (avoids noise like ID or T1).
const SAME_NAME_MIN_LENGTH = 4
// Object types to ignore for the same-name check (matched against objectType, case-insensitive).
const SAME_NAME_IGNORE_TYPES = /^(COLUMN|SYNONYM)$/i
