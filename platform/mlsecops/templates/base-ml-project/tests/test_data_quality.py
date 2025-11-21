import pandas as pd

from src.security_checks import check_label_distribution, check_nulls


def test_check_label_distribution_passes():
  df = pd.DataFrame({"label": [0, 0, 1, 1]})
  check_label_distribution(df, "label", threshold=0.9)


def test_check_label_distribution_fails_on_imbalance():
  df = pd.DataFrame({"label": [1, 1, 1, 1, 0]})
  try:
    check_label_distribution(df, "label", threshold=0.8)
  except ValueError:
    return
  assert False, "Expected ValueError for imbalanced labels"


def test_check_nulls_fails_on_high_nulls():
  df = pd.DataFrame({"a": [1, None, None, None]})
  try:
    check_nulls(df, max_null_fraction=0.5)
  except ValueError:
    return
  assert False, "Expected ValueError for high null fraction"
