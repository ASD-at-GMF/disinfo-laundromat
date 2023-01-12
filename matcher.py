import sys
import json
from pathlib import Path
import pandas as pd
import numpy as np


def find_direct_matches(
    feature_df: pd.DataFrame,
    feature: str,
    id_content="indicator_content",
) -> pd.DataFrame:
    # filter out invalid data
    feature_df = feature_df[["domain_name", id_content]]
    feature_df = feature_df[
        ~feature_df[id_content].isna() & ~feature_df[id_content].isnull()
    ]
    test_matches = pd.merge(feature_df, feature_df, how="inner", on=id_content)
    matches = test_matches[test_matches.domain_name_x != test_matches.domain_name_y]
    matches["match_type"] = feature
    matches = matches.rename(columns={id_content: "match_value"})
    return matches


def parse_whois_matches(feature_df: pd.DataFrame, whois_type="whois"):
    def convert_whois(data):
        whois_data = json.loads(str(data))
        whois_data["whois_domain"] = whois_data.pop("domain_name")
        return whois_data

    whois_df = feature_df.loc[
        feature_df["indicator_type"] == whois_type, :
    ].reset_index()
    whois_df["indicator_content"] = whois_df["indicator_content"].map(convert_whois)
    whois_df = pd.concat(
        [whois_df, pd.json_normalize(whois_df["indicator_content"])], axis=1
    )
    whois_features = ["registrar", "whois_server", "org", "city", "state", "country"]
    feature_matches = []
    for feature in whois_features:
        whois_feature_df = whois_df[["domain_name", feature]].set_index("domain_name")
        whois_feature_df = whois_feature_df[feature].explode().reset_index()
        whois_feature_df = whois_feature_df.replace("REDACTED FOR PRIVACY", np.nan)
        whois_feature_df = whois_feature_df.dropna()
        print(whois_feature_df)
        matches = find_direct_matches(
            whois_feature_df,
            feature=feature,
            id_content=feature,
        )
        feature_matches.append(matches)
    whois_matches = pd.concat(feature_matches)
    return whois_matches


def find_all_matches(indicators, result_dir=None) -> pd.DataFrame:
    matches_per_feature = []
    features_for_direct_matching = [
        "ip",
        "domain",
        "cert-domain",
        "cdn-domain",
        "domain_suffix",
        "domain",
        "uuid",
        "ga_id",
        "crypto-wallet",
        "ga_tag_id",
        "meta_social",
        "subnet",
        "verification_id",
        "yandex_tag_id",
    ]
    for feature in features_for_direct_matching:
        feature_df = indicators[indicators["indicator_type"] == feature]
        feature_matches = find_direct_matches(feature_df, feature)
        if result_dir:
            feature_matches.to_csv(f"{result_dir}/{feature}_matches.csv", index=False)
        matches_per_feature.append(feature_matches)
    whois_matches = parse_whois_matches(indicators)
    if result_dir:
        whois_matches.to_csv(f"{result_dir}/whois_matches.csv", index=False)
    matches_per_feature.append(whois_matches)
    all_matches = pd.concat(matches_per_feature)
    return all_matches


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Error! We need an input file and a result directory")
    else:
        indicator_file = sys.argv[1]
        if len(sys.argv) > 2:
            print(f"we'll save intermediary results to the directory {sys.argv[2]}")
            result_dir = sys.argv[2]
            Path(result_dir).mkdir(exist_ok=True)
        else:
            result_dir = None
        indicators = pd.read_csv(indicator_file)
        matches = find_all_matches(indicators, result_dir)
        print(f"{matches.shape[0]} overall matches found")
        final_results_filename = Path(indicator_file).stem + "_results.csv"
        matches.to_csv(final_results_filename, index=False)
