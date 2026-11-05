# RPostgres is GPL-3, so it is not declared in DESCRIPTION (permissive
# dependencies only). Tests that use a Postgres server load it by name.
postgres <- function() getExportedValue("RPostgres", "Postgres")()
