from typing import Tuple

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split


def split_features_labels(df: pd.DataFrame, label_col: str) -> Tuple[pd.DataFrame, pd.Series]:
  X = df.drop(columns=[label_col])
  y = df[label_col]
  return X, y


def train_baseline_model(df: pd.DataFrame, label_col: str = "label"):
  X, y = split_features_labels(df, label_col)
  X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

  model = LogisticRegression(max_iter=200)
  model.fit(X_train, y_train)
  score = model.score(X_test, y_test)

  return model, score
