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


def basic_preprocess(df: pd.DataFrame, feature: str) -> pd.DataFrame:
    df = df[["domain_name", feature]]
    return df[~df[feature].isna() & ~df[feature].isnull()].drop_duplicates()


# whois data
def convert_whois(data):
    try:
        whois_data = json.loads(str(data))
    except json.decoder.JSONDecodeError:
        whois_data = ast.literal_eval(data)
    # this keeps the property 'domain_name' from conflicting with our column
    if "domain_name" in whois_data:
        whois_data["whois_domain"] = whois_data.pop("domain_name")
    return whois_data


def whois_preprocess(df: pd.DataFrame, whois_feature: str) -> pd.DataFrame:
    whois_df = df.loc[df[INDICATOR_TYPE] == whois_feature, :].reset_index()
    whois_df[INDICATOR] = (
        whois_df[INDICATOR].map(convert_whois).map(partial(prefix_keys, prefix="whois"))
    )
    whois_df = pd.concat([whois_df, pd.json_normalize(whois_df[INDICATOR])], axis=1)

    return whois_df


def feature_df_preprocess(feature_df: pd.DataFrame, feature: str) -> pd.DataFrame:
    whois_feature_df = feature_df[[DOMAIN, feature]].set_index(DOMAIN)
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
    cert_df = df.loc[df[INDICATOR_TYPE] == cert_feature, :].reset_index()
    try:
        cert_df[INDICATOR] = cert_df[INDICATOR].map(json.loads)
    except json.JSONDecodeError:
        # this is bad and should be fixed by the change in crawler line 462
        cert_df[INDICATOR] = cert_df[INDICATOR].map(ast.literal_eval)
    cert_df[INDICATOR] = cert_df[INDICATOR].map(
        partial(prefix_keys, prefix="certificate")
    )
    cert_df = pd.concat([cert_df, pd.json_normalize(cert_df[INDICATOR])], axis=1)
    return cert_df


## Matching


def find_direct_matches(
    feature_df: pd.DataFrame,
    feature: str,
    comparison_df: Optional[pd.DataFrame] = None,
    indicator=INDICATOR,
) -> pd.DataFrame:
    # filter out invalid data
    feature_df = basic_preprocess(feature_df, indicator)
    if comparison_df is not None:
        comparison_df = basic_preprocess(comparison_df, indicator)
    else:
        comparison_df = feature_df
    test_matches = pd.merge(feature_df, comparison_df, how="inner", on=indicator)
    matches = test_matches[test_matches.domain_name_x != test_matches.domain_name_y]
    # deduplicating
    matches = matches[matches.domain_name_x < matches.domain_name_y]
    matches["match_type"] = feature
    matches = matches.rename(columns={indicator: "match_value"})
    return matches


def find_iou_matches(
    feature_df: pd.DataFrame,
    feature: str,
    comparison_df: Optional[pd.DataFrame] = None,
    threshold: float = 0.9,
) -> pd.DataFrame:
    # the better way to do this is to map the unique features to integers, e.g. with pandas indexing
    # and do this work in numpy/scipy
    def iou(set1, set2):
        return len(set1.intersection(set2)) / len(set1.union(set2))

    feature_sets = feature_df.groupby(DOMAIN)[INDICATOR].apply(set)
    if comparison_df is not None:
        comparison_sets = comparison_df.groupby(DOMAIN)[INDICATOR].apply(set)
        f_index = feature_sets.index.values
        c_index = comparison_sets.index.values
        iou_data = [
            {
                "domain_name_x": f_domain,
                "domain_name_y": c_domain,
                "match_value": round(
                    iou(feature_sets.loc[f_domain], comparison_sets.loc[c_domain]), 3
                ),
            }
            for f_domain in f_index
            for c_domain in c_index
        ]
    else:
        domain_index = feature_sets.index.values
        iou_data = []
        for indx1, domain1 in enumerate(domain_index[:-1]):
            for indx2, domain2 in enumerate(domain_index[indx1 + 1 :]):
                iou_data.append(
                    {
                        "domain_name_x": domain1,
                        "domain_name_y": domain2,
                        "match_value": round(
                            iou(feature_sets.loc[domain1], feature_sets.loc[domain2]), 3
                        ),
                    }
                )
    result = pd.DataFrame(iou_data)
    result["match_type"] = feature
    result = result[result["match_value"] >= threshold]
    return result


def parse_whois_matches(
    feature_df: pd.DataFrame,
    feature="whois",
    comparison_df: Optional[pd.DataFrame] = None,
):
    whois_df = whois_preprocess(feature_df, feature)
    if comparison_df is not None:
        whois_comparison_df = whois_preprocess(comparison_df, feature)
    else:
        whois_comparison_df = None
    feature_matches = []
    for sub_feature in WHOIS_FEATURES:
        whois_feature_df = feature_df_preprocess(whois_df, sub_feature)
        if whois_comparison_df is not None:
            whois_feature_comparison_df = feature_df_preprocess(
                whois_comparison_df, sub_feature
            )
        else:
            whois_feature_comparison_df = whois_feature_df
        matches = find_direct_matches(
            whois_feature_df,
            feature=sub_feature,
            comparison_df=whois_feature_comparison_df,
            indicator=sub_feature,
        )
        feature_matches.append(matches)
    whois_matches = pd.concat(feature_matches)
    return whois_matches


# this is very similar to whois and can be refactored
def parse_certificate_matches(
    feature_df: pd.DataFrame,
    feature="urlscan_certificate",
    comparison_df: Optional[pd.DataFrame] = None,
):
    cert_df = cert_preprocess(feature_df, feature)
    if comparison_df is not None:
        cert_comparison_df = cert_preprocess(comparison_df, feature)
    else:
        cert_comparison_df = None
    feature_matches = []
    for sub_feature in URLSCAN_CERT_FEATURES:
        cert_feature_df = feature_df_preprocess(cert_df, sub_feature)
        if cert_comparison_df is not None:
            cert_feature_comparison_df = feature_df_preprocess(
                cert_comparison_df, sub_feature
            )
        else:
            cert_feature_comparison_df = cert_feature_df
        matches = find_direct_matches(
            cert_feature_df,
            feature=sub_feature,
            comparison_df=cert_feature_comparison_df,
            indicator=sub_feature,
        )
        feature_matches.append(matches)
    cert_matches = pd.concat(feature_matches)
    return cert_matches


## Main program
FEATURE_MATCHING: Dict[str, str] = {
    "1-cert-domain" : "direct",
"1-crypto-wallet" : "direct",
"1-domain" : "direct",
"1-domain_suffix" : "direct",
"1-fb_pixel_id" : "direct",
"1-fb_pixel_id" : "direct",
"1-adobe_analytics_id" : "direct",
"3-sitemap_entries" : "direct",
"3-css_classes" : "direct",
"3-ipms_domain_iprangeowner_cidr" : "direct",
"3-ipms_domain_iprangeowner_ownerName" : "direct",
"3-ipms_domain_iprangeowner_address" : "direct",
"3-ipms_domain_nameserver" : "direct",
"3-ipms_domain_otheripused" : "direct",
"3-ipms_siteonthisip_now" : "direct",
"3-ipms_siteonthisip_before" : "direct",
"3-ipms_siteonthisip_broken" : "direct",
"3-ipms_useragents" : "direct",
"1-ip_shodan_hostnames" : "direct",
"3-ip_shodan_ports" : "direct",
"2-ip_shodan_vuln" : "direct",
"3-ip_shodan_cpe" : "direct",
"1-ga_id" : "direct",
"1-ga_tag_id" : "direct",
"1-ip" : "direct",
"1-verification_id" : "direct",
"1-yandex_tag_id" : "direct",
"2-subnet" : "direct",
"3-cdn-domain" : "direct",
"3-cms" : "direct",
"3-css-classes" : "iou",
"3-header-nonstd-value" : "direct",
"3-header-server" : "direct",
"3-id_tags" : "iou",
"3-iframe_id_tags" : "iou",
"3-link_href" : "direct",
"3-meta_generic" : "direct",
"3-meta_social" : "direct",
"3-script_src" : "direct",
"3-uuid" : "direct",
"3-whois_creation_date" : "direct",
"3-whois_server" : "direct",
"3-whois-registrar" : "direct",
"3-wp-blocks" : "iou",
"3-wp-categories" : "iou",
"3-wp-pages" : "iou",
"3-wp-posts" : "iou",
"3-wp-tags" : "iou",
"3-wp-users" : "iou",

}

WHOIS_FEATURES = [
    "whois-registrar",
    "whois-whois_server",
    "whois-org",
    "whois-city",
    "whois-state",
    "whois-country",
]

URLSCAN_CERT_FEATURES = ["certificate-subjectName"]

DICT_FEATURES = {"whois": WHOIS_FEATURES, "certificate": URLSCAN_CERT_FEATURES}

# to add a new method, write a function with the expected arguments:
# - feature_df,
# - feature,
# - comparison_df (with default value Non)
# then add the method to this dictionary. to use the method on a feature, set the value
# of a feature in the FEATURE_MATCHING dictionary above to the label/key you use in this dictionary.
methods = {
    "direct": find_direct_matches,
    "whois": parse_whois_matches,
    "certificate": parse_certificate_matches,
    "iou": find_iou_matches,
    # "dict_direct_match"
    # "intersection"
    # "iou"
    # "abs_difference_vs_threshold"
}
# todo add 'any in list" match


def find_matches(data, comparison=None, result_dir=None) -> pd.DataFrame:
    matches_per_feature = []
    # Get unique values from 'column_name'
    unique_values = data['indicator_type'].unique()
    for value in unique_values:
        if value not in FEATURE_MATCHING.keys():
            FEATURE_MATCHING[value] = 'direct'
            print(f"\"{value}\" : \"direct\",")

    for feature, method in FEATURE_MATCHING.items():
        feature_df = data[data[INDICATOR_TYPE] == feature]
        if feature_df.shape[0] > 1:
            if comparison is not None:
                comparison_df = comparison[comparison[INDICATOR_TYPE] == feature]
            else:
                comparison_df = None
            feature_matches = methods[method](
                feature_df=feature_df, feature=feature, comparison_df=comparison_df
            )
            matches_per_feature.append(feature_matches)
            if result_dir:
                feature_matches.to_csv(
                    f"{result_dir}/{feature}_matches.csv", index=False
                )
    all_matches = pd.concat(matches_per_feature)
    return all_matches


def compare_indicator_files(file1, file2, result_dir=None, result_file=None):
    data1 = pd.read_csv(file1)
    data2 = pd.read_csv(file2)
    if not result_file:
        result_file = f"{Path(file1).stem}_{Path(file2).stem}_results.csv"
    matches = find_matches(data1, data2, result_dir=result_dir)
    print(f"Matches found: {matches.shape[0]}")
    print(
        f"Summary of matches:\n{matches.groupby('match_type')['match_value'].count()}"
    )
    matches.to_csv(result_file, index=False)


def pairwise_comparison(input_file, result_dir=None, result_file=None):
    data = pd.read_csv(input_file)
    if not result_file:
        result_file = Path(input_file).stem + "_results.csv"
    matches = find_matches(data, result_dir=result_dir)
    print(f"Matches found: {matches.shape[0]}")
    print(
        f"Summary of matches:\n{matches.groupby('match_type')['match_value'].count()}"
    )
    matches.to_csv(result_file, index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Match indicators across sites.", add_help=False
    )
    parser.add_argument(
        "-f", "--input-file", type=str, help="file of indicators to match",
        default="./indicators_output.csv"
    )
    parser.add_argument(
        "-r",
        "--result-dir",
        type=str,
        help="directory to save intermediary match results",
        required=False,
        default="./tmp/"
    )
    parser.add_argument(
        "-o",
        "--output-file",
        type=str,
        help="file to save final list of match results",
        required=False,
        default="matching_results.csv"
    ) 

    parser.add_argument(
        "-c",
        "--comparison-type",
        type=str,
        help="type of comparison to run, pairwise or one-to-one compare",
        required=False,
        default="pairwise"
    ) 
    parser.add_argument(
        "-cf",
        "--compare-file",
        type=str,
        help="file of indicators to compare against",
        required=False,
        default="./comparison_indicators.csv"
    )

    args = parser.parse_args()

    result_dir = args.result_dir
    result_file = args.output_file

    if result_dir:
        print(f"we'll save intermediary results to the directory {args.result_dir}")
        Path(result_dir).mkdir(exist_ok=True)

    if args.comparison_type == "compare":
        compare_indicator_files(
            file1=args.input_file,
            file2=args.compare_file,
            result_dir=result_dir,
            result_file=result_file,
        )
    else:
        pairwise_comparison(
            input_file=args.input_file, result_dir=result_dir, result_file=result_file
        )
