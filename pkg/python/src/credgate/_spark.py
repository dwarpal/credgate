"""Sampling of Spark DataFrames inside the cluster (the spec's "Spark tables"
rules); only the sampled rows reach the driver."""

from __future__ import annotations

from typing import Any


def is_spark(data: Any) -> bool:
    """A PySpark DataFrame, classic or Spark Connect."""
    return type(data).__module__.startswith("pyspark.") and type(data).__name__ == "DataFrame"


def sample_rows(df: Any, sample: int, seed: int) -> Any:
    """The sampled rows, with the table's row count and the sample method."""
    from pyspark.sql import functions as F
    from pyspark.sql import types as T

    from .scan import _Sampled

    skipped = (T.ArrayType, T.MapType, T.StructType, T.BinaryType)
    whole = (T.ByteType, T.ShortType, T.IntegerType, T.LongType)
    names = [f.name for f in df.schema.fields]
    read = []
    for f in df.schema.fields:
        if isinstance(f.dataType, skipped):
            continue
        col = F.col("`" + f.name.replace("`", "``") + "`")
        t = f.dataType
        if isinstance(t, whole) or (isinstance(t, T.DecimalType) and t.scale == 0):
            col = col.cast("string")
        elif isinstance(t, T.DecimalType):
            col = col.cast("double")
        read.append((f.name, col.alias(f"c{len(read)}")))
    n = df.count()
    selected = df.select(*[c for _, c in read]) if read else None
    if n > sample and selected is not None:
        selected = selected.sample(False, min(1.0, 1.2 * sample / n), seed).limit(sample)
        method = "spark-sample"
    else:
        method = "all"
    rows = selected.collect() if selected is not None else []
    values = {name: [r[i] for r in rows] for i, (name, _) in enumerate(read)}
    return _Sampled({name: values.get(name, []) for name in names}, n, method)
