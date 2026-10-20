// How assets are grouped in the Breakdown under Assets. Edit this file if a tool lands in the wrong group:
// then reload the page (no rebuild needed). Rules run top to bottom and the first match wins.
// Each asset is described by: tool (toolName, e.g. SNOWFLAKE), toolType (DB / ETL / REPORT),
// objectType (e.g. TABLE, VIEW) and container (containerObjectType, e.g. SQL_STORED_PROCEDURE).
const CATEGORY_ORDER = [
  { id: 'etl', name: 'ETLs' },
  { id: 'sp', name: 'Stored Procedures & SQL Files' },
  { id: 'db', name: 'DB Objects' },
  { id: 'files', name: 'Files & Analysis Services' },
  { id: 'reports', name: 'Reports, Analytics & Information Consumers' },
  { id: 'other', name: 'Other / unclassified' },
]

// Database engines: an asset from one of these is a DB object even if its object type or container mentions FILE.
const DB_ENGINES = /^(IMPALA|HIVE|SNOWFLAKE|ORACLE|SQLS|SQL_?SERVER|MSSQL|POSTGRES|MYSQL|TERADATA|REDSHIFT|BIGQUERY|DB2|SYBASE|HANA|DATABRICKS|TRINO|PRESTO|VERTICA|NETEZZA|SPANNER|SYNAPSE|UNK)/
function classify(c) {
  let type = String(c.toolType || '').toUpperCase()
  if (type === 'DATABASE') type = 'DB'          // some tenants send DATABASE instead of DB
  const tool = String(c.tool || '').toUpperCase()
  const obj = `${c.objectType || ''} ${c.container || ''}`.toUpperCase()
  if (type === 'REPORT') return 'reports'
  if (/PROCEDURE|SQL_?FILE|SQL FILE|SCRIPT|FUNCTION/.test(obj)) return 'sp'
  if (type === 'ETL') return 'etl'
  if (/^(FILE|CSV|EXCEL|XLS|JSON|XML|PARQUET|SSAS|AAS|CUBE|OLAP|ANALYSIS)/.test(tool)) return 'files'
  if (DB_ENGINES.test(tool)) return 'db'
  if (/FILE|CUBE|ANALYSIS|OLAP|TABULAR/.test(obj)) return 'files'
  if (type === 'DB') return 'db'
  return 'other'
}
