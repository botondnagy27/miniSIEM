import pandas as pd
from datetime import timedelta

def detect_rule_based_threats(df: pd.DataFrame) -> pd.DataFrame:

    alerts = []
