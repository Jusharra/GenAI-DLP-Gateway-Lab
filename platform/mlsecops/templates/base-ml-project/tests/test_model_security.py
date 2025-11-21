import pandas as pd

from src.security_checks import validate_training_data


def test_validate_training_data_smoke():
  df = pd.DataFrame(
    {
      "feature1": [1, 2, 3, 4],
      "label": [0, 1, 0, 1],
    }
  )
  validate_training_data(df, label_col="label")
