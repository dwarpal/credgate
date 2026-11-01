# Inventory and discovery

Where PII is, across tables: in-memory data frames, Arrow, DuckDB, Spark and
BigQuery all produce the same inventory.

::: credgate.pii_inventory
::: credgate.Inventory
::: credgate.InventoryRow
::: credgate.read_inventory

## BigQuery

::: credgate.bigquery
    options:
      show_root_heading: false
      members: [scan_pii, pii_inventory, inventory_dataset, sample_query, CostLimitError]
