import argparse
import ast
import json
import logging
import traceback
from functools import partial
from itertools import chain
from pathlib import Path
from typing import Any, Dict, Callable

import numpy as np
import pandas as pd
from pandas.api.types import is_list_like

from modules.indicators import (EMBEDDED_IDS, FINANCIAL_IDS, SOCIAL_MEDIA_IDS,
                                TRACKING_IDS)

## Preprocessing

DOMAIN = "domain_name"
INDICATOR_TYPE = "indicator_type"
INDICATOR = "indicator_content"
MATCH_TYPE = "match_type"
MATCH_VALUE = "match_value"


def basic_preprocess(df: pd.DataFrame, feature: str) -> pd.DataFrame:
    df = df[[DOMAIN, feature]]
    df = df[~df[feature].isna() & ~df[feature].isnull()]

    return df

def column_contains_list_string(column: pd.Series) -> bool:
    # Note: this works off the assumption that all values will have the same type
    try:
        return column.iloc[0].startswith("[")
    except AttributeError:
        return False

def column_contains_set_string(column: pd.Series) -> bool:
    try:
        return column.iloc[0].startswith("{")
    except AttributeError:
        return False

def group_indicators(df: pd.DataFrame) -> pd.Series:
    if is_list_like(df[INDICATOR].iloc[0]):
        return df.groupby(DOMAIN)[INDICATOR].agg(lambda x: set(chain.from_iterable(x)))
    elif column_contains_list_string(df[INDICATOR]) or column_contains_set_string(df[INDICATOR]):
        df_copy = df.copy() # avoid side effects with ast.literal
        df_copy[INDICATOR] = df_copy[INDICATOR].map(ast.literal_eval)
        return df_copy.groupby(DOMAIN)[INDICATOR].agg(lambda x: set(chain.from_iterable(x)))
    else:
        return df.groupby(DOMAIN)[INDICATOR].apply(set)



# whois data
def convert_whois(data):
    try:
        whois_data = json.loads(str(data))
    except json.decoder.JSONDecodeError:
        whois_data = ast.literal_eval(data)
    # this keeps the property 'domain_name' from conflicting with our column
    if DOMAIN in whois_data:
        whois_data["whois_domain"] = whois_data.pop(DOMAIN)
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
def prefix_keys(data_dict: dict[str, Any], prefix: str) -> dict[str, Any]:
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


def direct_match(
    feature_df: pd.DataFrame,
    feature: str,
    comparison_df: pd.DataFrame,
    indicator=INDICATOR,
) -> pd.DataFrame:
    # filter out invalid data
    feature_df = basic_preprocess(feature_df, indicator)
    comparison_df = basic_preprocess(comparison_df, indicator)
    test_matches = pd.merge(feature_df, comparison_df, how="inner", on=indicator)
    # deduplicating
    matches = test_matches[test_matches.domain_name_x < test_matches.domain_name_y]
    # note this throws a false positive SettingWithCopyWarning; the behavior is OK
    matches[MATCH_TYPE] = feature
    matches = matches.rename(columns={indicator: MATCH_VALUE})
    return matches.reset_index(drop=True)

# TODO: Add a partial string match function

def iou_match(
    feature_df: pd.DataFrame,
    feature: str,
    comparison_df: pd.DataFrame,
    threshold: float = 0.9,
) -> pd.DataFrame:
    # Define IOU function
    def iou(set1, set2):
        return len(set1.intersection(set2)) / (len(set1.union(set2)) + 0.000001)

    # Convert data to sets
    feature_sets = group_indicators(feature_df).to_dict()
    comparison_sets = group_indicators(comparison_df).to_dict()

    # Generate IOU data
    iou_data = [
        {
            "domain_name_x": f_domain,
            "domain_name_y": c_domain,
            MATCH_VALUE: round(iou(feature_sets[f_domain], comparison_sets[c_domain]), 3),
            "matched_on": feature_sets[f_domain].intersection(comparison_sets[c_domain])

        }
        for f_domain in feature_sets
        for c_domain in comparison_sets
        if f_domain < c_domain # deduplicate
    ]

    # Create DataFrame from IOU data
    result = pd.DataFrame(iou_data, columns=["domain_name_x", "domain_name_y", "matched_on", MATCH_TYPE, MATCH_VALUE])
    if not result.empty:
        result[MATCH_TYPE] = feature
        result = result[result[MATCH_VALUE] >= threshold]

    return result

def any_in_list_match(
        feature_df: pd.DataFrame,
        comparison_df: pd.DataFrame,
        feature: str,
):
    feature_sets = group_indicators(feature_df).to_dict()
    comparison_sets = group_indicators(comparison_df).to_dict()
    matches = [
        {
            "domain_name_x": f_domain,
            "domain_name_y": c_domain,
            MATCH_TYPE: feature,
            "matched_on": feature_sets[f_domain].intersection(comparison_sets[c_domain])

        }
        for f_domain in feature_sets
        for c_domain in comparison_sets
        if f_domain < c_domain # deduplicate
    ]
    matches_df = pd.DataFrame(matches, columns=["domain_name_x", "domain_name_y", "matched_on", MATCH_TYPE, MATCH_VALUE])
    if not matches_df.empty:
        matches_df = matches_df[matches_df["matched_on"].map(lambda d: len(d)) > 0]
        matches_df[MATCH_VALUE] = True
    return matches_df.reset_index(drop=True)

def parse_whois_matches(
    feature_df: pd.DataFrame,
    comparison_df: pd.DataFrame,
    feature="whois",
):
    whois_df = whois_preprocess(feature_df, feature)
    whois_comparison_df = whois_preprocess(comparison_df, feature)

    feature_matches = []
    for sub_feature in WHOIS_FEATURES:
        whois_feature_df = feature_df_preprocess(whois_df, sub_feature)
        whois_feature_comparison_df = feature_df_preprocess(whois_comparison_df, sub_feature)
        matches = direct_match(
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
    comparison_df: pd.DataFrame,
    feature="urlscan_certificate",
):
    cert_df = cert_preprocess(feature_df, feature)
    cert_comparison_df = cert_preprocess(comparison_df, feature)

    feature_matches = []
    for sub_feature in URLSCAN_CERT_FEATURES:
        cert_feature_df = feature_df_preprocess(cert_df, sub_feature)
        cert_feature_comparison_df = feature_df_preprocess(
            cert_comparison_df, sub_feature
        )
        matches = direct_match(
            cert_feature_df,
            feature=sub_feature,
            comparison_df=cert_feature_comparison_df,
            indicator=sub_feature,
        )
        feature_matches.append(matches)
    cert_matches = pd.concat(feature_matches)
    return cert_matches


## Main program
FEATURE_MATCHING: dict[str, Callable[[pd.DataFrame, str, pd.DataFrame], pd.DataFrame]] = {
"1-cert-domain" : direct_match,
"1-crypto-wallet" : direct_match,
"1-domain" : direct_match,
"1-domain_suffix" : direct_match,
"1-fb_pixel_id" : direct_match,
"1-adobe_analytics_id" : direct_match,
"3-sitemap_entries" : direct_match,
"3-ipms_domain_iprangeowner_cidr" : direct_match,
"3-ipms_domain_iprangeowner_ownerName" : direct_match,
"3-ipms_domain_iprangeowner_address" : direct_match,
"3-ipms_domain_nameserver" : iou_match,
"3-ipms_domain_otheripused" : iou_match,
"3-ipms_siteonthisip_now" : iou_match,
"3-ipms_siteonthisip_before" : iou_match,
"3-ipms_siteonthisip_broken" : iou_match,
"3-ipms_useragents" : iou_match,
"1-ip_shodan_hostnames" : direct_match,
"3-ip_shodan_ports" : iou_match,
"2-ip_shodan_vuln" : iou_match,
"3-ip_shodan_cpe" : iou_match,
"1-ga_id" : direct_match,
"1-ga_tag_id" : direct_match,
"1-ip" : direct_match,
"1-verification_id" : direct_match,
"1-yandex_tag_id" : direct_match,
"2-subnet" : direct_match,
"3-cdn-domain" : iou_match,
"3-cms" : direct_match,
"3-css_classes" : iou_match,
"3-header-nonstd-value" : direct_match,
"3-header-server" : direct_match,
"3-id_tags" : iou_match,
"3-iframe_id_tags" : iou_match,
"3-link_href" : iou_match,
"3-meta_generic" : iou_match,
"3-meta_social" : direct_match,
"3-script_src" : iou_match,
"3-uuid" : direct_match,
"3-whois_creation_date" : direct_match,
"3-whois_server" : direct_match,
"3-whois-registrar" : direct_match,
"3-wp-blocks" : iou_match,
"3-wp-categories" : iou_match,
"3-wp-pages" : iou_match,
"3-wp-posts" : iou_match,
"3-wp-tags" : iou_match,
"3-wp-users" : iou_match,
"2-urlscan_globalvariable": iou_match,
"2-urlscan_cookies": iou_match,
"2-urlscan_consolemessages": iou_match,
"2-urlscan_asn": direct_match,
"2-urlscan_domainsonpage": iou_match,
"2-urlscan_urlssonpage" : iou_match,
"2-urlscanhrefs" : iou_match,
"2-techstack" : iou_match,
"3-footer-text": direct_match,
"4-outbound-domain": iou_match,
"2-ads_txt": iou_match

}

FEATURE_MATCHING.update({financial_id: direct_match for financial_id in FINANCIAL_IDS})
FEATURE_MATCHING.update({embedded_id: direct_match for embedded_id in EMBEDDED_IDS})
FEATURE_MATCHING.update({social_id: direct_match for social_id in SOCIAL_MEDIA_IDS})
FEATURE_MATCHING.update({tracking_id: direct_match for tracking_id in TRACKING_IDS})

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


def find_matches(data, comparison=None, result_dir=None) -> pd.DataFrame:
    matches_per_feature = []
    unique_features = data[INDICATOR_TYPE].unique()

    if comparison is None:
        comparison = data

    for feature in unique_features:
        match_func = FEATURE_MATCHING.get(feature, None)
        if not match_func:
            logging.error(f"MISSING FEATURE MATCHING METHOD FOR: {feature}")
            continue
        try:
            logging.info(f"Matching {feature} with method: {match_func.__name__}")
        except AttributeError as e:
            logging.info(f"Matching {feature} with method: {match_func.func.__name__}, {match_func.keywords}, {e}")
        feature_df = data[data[INDICATOR_TYPE] == feature]
        comparison_df = comparison[comparison[INDICATOR_TYPE] == feature]
        try:
            feature_matches = match_func(
                feature_df=feature_df,  # type: ignore
                feature=feature,
                comparison_df=comparison_df
            )
            matches_per_feature.append(feature_matches)
            if result_dir:
                feature_matches.to_csv(
                    f"{result_dir}/{feature}_matches.csv", index=False
                )
        except Exception as e:
            logging.error(f"Error ({e}) matching feature {feature}: {traceback.print_stack()}")
            continue
    all_matches = pd.concat(matches_per_feature)
    return all_matches


def define_output_filename(file1, file2 = None):
    if file2:
        return f"{Path(file1).stem}_{Path(file2).stem}_results.csv"
    return f"{Path(file1).stem}_results.csv"
        

def main(input_file, compare_file, result_dir, output_file, comparison_type):
    if result_dir:
        logging.info(f"we'll save intermediary results to the directory {result_dir}")
        Path(result_dir).mkdir(exist_ok=True)

    data1 = pd.read_csv(input_file)
    if comparison_type == "compare" and compare_file:
        data2 = pd.read_csv(compare_file)
        matches: pd.DataFrame = find_matches(data1, data2, result_dir=result_dir)
    else:
        matches = find_matches(data1, result_dir=result_dir)
    logging.info(f"Matches found: {matches.shape[0]}")
    logging.info(
        f"Summary of matches:\n{matches.groupby('match_type')['match_value'].count()}"
    )
    if not output_file:
        output_file = define_output_filename(input_file, compare_file)
    matches.to_csv(output_file, index=False)


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
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )
    args = parser.parse_args()

    main(**vars(args))
