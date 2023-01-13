import sys
import argparse
import json
import ast
from pathlib import Path
import pandas as pd
import numpy as np
from typing import Optional, Dict, Any
from functools import partial

## Preprocessing

DOMAIN = "domain_name"
INDICATOR_TYPE = "indicator_type"
INDICATOR = "indicator_content"

methods = {
    "direct_match": 1,
    "dict_direct_match": 1,
    "intersection": 1,
    "iou": 1,
    "abs_difference_vs_threshold": 1,
}

DIRECT_MATCHING_FEATURES = [
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
    "global_variable",  # compare this directly as a string
    "techstack",
]

WHOIS_FEATURES = ["registrar", "whois_server", "org", "city", "state", "country"]

URLSCAN_CERT_FEATURES = ["certificate-subjectName", "certificate-issuer"]


def basic_preprocess(df: pd.DataFrame, feature: str) -> pd.DataFrame:
    df = df[["domain_name", feature]]
    return df[~df[feature].isna() & ~df[feature].isnull()].drop_duplicates()


# whois data
def convert_whois(data):
    try:
        whois_data = json.loads(str(data))
    except json.decoder.JSONDecodeError:
        whois_data = json.loads(data)
    # this keeps the property 'domain_name' from conflicting with our column
    whois_data["whois_domain"] = whois_data.pop("domain_name")
    return whois_data


def whois_preprocess(df: pd.DataFrame, whois_feature: str) -> pd.DataFrame:
    whois_df = df.loc[df["indicator_type"] == whois_feature, :].reset_index()
    whois_df["indicator_content"] = whois_df["indicator_content"].map(convert_whois)
    whois_df = pd.concat(
        [whois_df, pd.json_normalize(whois_df["indicator_content"])], axis=1
    )
    return whois_df


def feature_df_preprocess(feature_df: pd.DataFrame, feature: str) -> pd.DataFrame:
    whois_feature_df = feature_df[["domain_name", feature]].set_index("domain_name")
    whois_feature_df = whois_feature_df[feature].explode().reset_index()
    whois_feature_df = (
        whois_feature_df.replace("REDACTED FOR PRIVACY", np.nan)
        .dropna()
        .drop_duplicates()
    )
    return whois_feature_df


# urlscan certificate
def prefix_keys(data_dict: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    new_dict = {}
    for key in data_dict.keys():
        new_dict[f"{prefix}-{key}"] = data_dict[key]
    return new_dict


def cert_preprocess(df: pd.DataFrame, cert_feature: str) -> pd.DataFrame:
    cert_df = df.loc[df["indicator_type"] == cert_feature, :].reset_index()
    try:
        cert_df["indicator_content"] = cert_df["indicator_content"].map(json.loads)
    except json.JSONDecodeError:
        # this is bad and should be fixed by the change in crawler line 462
        cert_df["indicator_content"] = cert_df["indicator_content"].map(
            ast.literal_eval
        )
    cert_df["indicator_content"] = cert_df["indicator_content"].map(
        partial(prefix_keys, prefix="certificate")
    )
    cert_df = pd.concat(
        [cert_df, pd.json_normalize(cert_df["indicator_content"])], axis=1
    )
    return cert_df


## Matching


def find_direct_matches(
    feature_df: pd.DataFrame,
    feature: str,
    comparison_df: Optional[pd.DataFrame] = None,
    id_content="indicator_content",
) -> pd.DataFrame:
    # filter out invalid data
    feature_df = basic_preprocess(feature_df, id_content)
    if comparison_df is not None:
        comparison_df = basic_preprocess(comparison_df, id_content)
    else:
        comparison_df = feature_df
    test_matches = pd.merge(feature_df, comparison_df, how="inner", on=id_content)
    matches = test_matches[test_matches.domain_name_x != test_matches.domain_name_y]
    # deduplicating
    matches = matches[matches.domain_name_x < matches.domain_name_y]
    matches["match_type"] = feature
    matches = matches.rename(columns={id_content: "match_value"})
    return matches


def parse_whois_matches(
    feature_df: pd.DataFrame,
    whois_feature="whois",
    comparison_df: Optional[pd.DataFrame] = None,
):
    whois_df = whois_preprocess(feature_df, whois_feature)
    if comparison_df is not None:
        whois_comparison_df = whois_preprocess(comparison_df, whois_feature)
    else:
        whois_comparison_df = None
    feature_matches = []
    for feature in WHOIS_FEATURES:
        whois_feature_df = feature_df_preprocess(whois_df, feature)
        if whois_comparison_df is not None:
            whois_feature_comparison_df = feature_df_preprocess(
                whois_comparison_df, feature
            )
        else:
            whois_feature_comparison_df = whois_feature_df
        matches = find_direct_matches(
            whois_feature_df,
            feature=feature,
            comparison_df=whois_feature_comparison_df,
            id_content=feature,
        )
        feature_matches.append(matches)
    whois_matches = pd.concat(feature_matches)
    return whois_matches


# this is very similar to whois and can be refactored
def parse_certificate_matches(
    feature_df: pd.DataFrame,
    certificate_feature="urlscan_certificate",
    comparison_df: Optional[pd.DataFrame] = None,
):
    cert_df = cert_preprocess(feature_df, certificate_feature)
    if comparison_df is not None:
        cert_comparison_df = cert_preprocess(comparison_df, certificate_feature)
    else:
        cert_comparison_df = None
    feature_matches = []
    for feature in URLSCAN_CERT_FEATURES:
        cert_feature_df = feature_df_preprocess(cert_df, feature)
        if cert_comparison_df is not None:
            cert_feature_comparison_df = feature_df_preprocess(
                cert_comparison_df, feature
            )
        else:
            cert_feature_comparison_df = cert_feature_df
        matches = find_direct_matches(
            cert_feature_df,
            feature=feature,
            comparison_df=cert_feature_comparison_df,
            id_content=feature,
        )
        feature_matches.append(matches)
    cert_matches = pd.concat(feature_matches)
    return cert_matches


def find_indicator_matches(data, corpus, result_dir=None) -> pd.DataFrame:
    matches_per_feature = []
    for feature in DIRECT_MATCHING_FEATURES:
        feature_df = data[data["indicator_type"] == feature]
        comparison_df = corpus[corpus["indicator_type"] == feature]
        if feature_df.shape[0] > 1:
            feature_matches = find_direct_matches(
                feature_df, feature, comparison_df=comparison_df
            )
            matches_per_feature.append(feature_matches)
            if result_dir:
                feature_matches.to_csv(
                    f"{result_dir}/{feature}_matches.csv", index=False
                )
    whois_matches = parse_whois_matches(feature_df=data, comparison_df=corpus)
    if result_dir:
        whois_matches.to_csv(f"{result_dir}/whois_matches.csv", index=False)
    matches_per_feature.append(whois_matches)
    cert_matches = parse_certificate_matches(data)
    if result_dir:
        cert_matches.to_csv(f"{result_dir}/cert_matches.csv", index=False)
    matches_per_feature.append(cert_matches)
    all_matches = pd.concat(matches_per_feature)
    return all_matches


def find_pairwise_matches(data, result_dir=None) -> pd.DataFrame:
    matches_per_feature = []

    for feature in DIRECT_MATCHING_FEATURES:
        feature_df = data[data["indicator_type"] == feature]
        feature_matches = find_direct_matches(feature_df, feature)
        if result_dir:
            feature_matches.to_csv(f"{result_dir}/{feature}_matches.csv", index=False)
        matches_per_feature.append(feature_matches)
    whois_matches = parse_whois_matches(data)
    if result_dir:
        whois_matches.to_csv(f"{result_dir}/whois_matches.csv", index=False)
    matches_per_feature.append(whois_matches)
    cert_matches = parse_certificate_matches(data)
    if result_dir:
        cert_matches.to_csv(f"{result_dir}/cert_matches.csv", index=False)
    matches_per_feature.append(cert_matches)
    all_matches = pd.concat(matches_per_feature)
    return all_matches


def compare_indicator_files(file1, file2, result_dir=None, result_file=None):
    data1 = pd.read_csv(file1)
    data2 = pd.read_csv(file2)
    if not result_file:
        result_file = f"{Path(file1).stem}_{Path(file2).stem}_results.csv"
    matches = find_indicator_matches(data1, data2, result_dir=result_dir)
    print(f"Matches found: {matches.shape[0]}")
    print(
        f"Summary of matches:\n{matches.groupby('match_type')['match_value'].count()}"
    )
    matches.to_csv(result_file, index=False)


def pairwise_comparison(input_file, result_dir=None, result_file=None):
    data = pd.read_csv(input_file)
    if not result_file:
        result_file = Path(input_file).stem + "_results.csv"
    matches = find_pairwise_matches(data, result_dir=result_dir)
    print(f"Matches found: {matches.shape[0]}")
    print(
        f"Summary of matches:\n{matches.groupby('match_type')['match_value'].count()}"
    )
    matches.to_csv(result_file, index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Match indicators across sites.", add_help=False
    )
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "-f", "--file", type=str, help="file of indicators to match"
    )
    parent_parser.add_argument(
        "--result-dir",
        type=str,
        help="directory to save intermediary match results",
        required=False,
    )
    parent_parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="file to save final list of match results",
        required=False,
    )
    subparsers = parser.add_subparsers(help="commands", dest="command")

    pairwise_parser = subparsers.add_parser(
        "pairwise",
        help="run to do pairwise matching in a corpus",
        parents=[parent_parser],
    )

    file_parser = subparsers.add_parser(
        "compare",
        help="run two files of indicators against each other",
        parents=[parent_parser],
    )
    file_parser.add_argument(
        "-f2",
        "--file2",
        type=str,
        help="file of indicators to compare against",
        required=True,
    )

    args = parser.parse_args(sys.argv[1:])

    result_dir = args.result_dir
    result_file = args.output

    if result_dir:
        print(f"we'll save intermediary results to the directory {args.result_dir}")
        Path(result_dir).mkdir(exist_ok=True)

    if args.command == "compare":
        compare_indicator_files(
            file1=args.file1,
            file2=args.file2,
            result_dir=result_dir,
            result_file=result_file,
        )
    else:
        pairwise_comparison(
            input_file=args.file, result_dir=result_dir, result_file=result_file
        )
