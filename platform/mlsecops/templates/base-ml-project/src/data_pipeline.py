from typing import Any

import pandas as pd


def load_data(source: str) -> pd.DataFrame:
  # Placeholder: read from CSV, DB, or other source
  df = pd.read_csv(source)
  return df


def basic_clean(df: pd.DataFrame) -> pd.DataFrame:
  # Placeholder: add null handling, type coercion, etc.
  return df.dropna()


def run_pipeline(source: str) -> pd.DataFrame:
  df = load_data(source)
  df = basic_clean(df)
  return df
