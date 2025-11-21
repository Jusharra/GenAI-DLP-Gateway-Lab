from typing import Any

import pandas as pd


def check_label_distribution(df: pd.DataFrame, label_col: str, threshold: float = 0.9):
  counts = df[label_col].value_counts(normalize=True)
  max_frac = counts.max()

  if max_frac > threshold:
    raise ValueError(
      f"Label imbalance detected. Max class fraction={max_frac:.2f} > {threshold}"
    )


def check_nulls(df: pd.DataFrame, max_null_fraction: float = 0.3):
  null_fraction = df.isnull().mean().max()
  if null_fraction > max_null_fraction:
    raise ValueError(
      f"High null fraction detected in at least one column: {null_fraction:.2f}"
    )


def validate_training_data(df: pd.DataFrame, label_col: str):
  """
  High-level training data validation for MLSecOps:
  - basic null checks
  - label imbalance checks
  Future:
  - PII detection
  - distribution drift vs baseline
  """
  check_nulls(df)
  check_label_distribution(df, label_col)
