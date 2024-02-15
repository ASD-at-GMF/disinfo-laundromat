import argparse
from pathlib import Path
import pandas as pd
from preprocess import basic_preprocess,cert_preprocess, feature_df_preprocess, whois_preprocess 
from typing import Optional, Dict

## Preprocessing

DOMAIN = "domain_name"
INDICATOR_TYPE = "indicator_type"
INDICATOR = "indicator_content"


## Matching


def find_direct_matches(
    feature_df: pd.DataFrame,
    feature: str,
    comparison_df: pd.DataFrame,
    indicator=INDICATOR,
) -> pd.DataFrame:
    # filter out invalid data
    feature_df = basic_preprocess(feature_df, indicator)
    comparison_df = basic_preprocess(comparison_df, indicator)
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
    comparison_df: pd.DataFrame,
    threshold: float = 0.9,
) -> pd.DataFrame:
    # Define IOU function
    def iou(set1, set2):
        return len(set1.intersection(set2)) / (len(set1.union(set2)) + 0.000001)

    # Convert feature data to sets
    feature_sets = feature_df.groupby(DOMAIN)[INDICATOR].apply(lambda x: set.union(*map(set, x))).to_dict()

    # Convert comparison data to sets
    comparison_sets = comparison_df.groupby(DOMAIN)[INDICATOR].apply(lambda x: set.union(*map(set, x))).to_dict()

    # Generate IOU data
    iou_data = [
        {
            "domain_name_x": f_domain,
            "domain_name_y": c_domain,
            "match_value": round(iou(feature_sets[f_domain], comparison_sets[c_domain]), 3),
            "matched_on": feature_sets[f_domain]

        }
        for f_domain in feature_sets
        for c_domain in comparison_sets
        if f_domain != c_domain
    ]

    # Create DataFrame from IOU data
    result = pd.DataFrame(iou_data)
    if result.empty:
        return result
    result["match_type"] = feature
    result = result[result["match_value"] >= threshold]

    return result

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
        whois_feature_comparison_df = feature_df_preprocess(
            whois_comparison_df, sub_feature
        )
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
"1-adobe_analytics_id" : "direct",
"3-sitemap_entries" : "direct",
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
"3-ip_shodan_ports" : "iou",
"2-ip_shodan_vuln" : "iou",
"3-ip_shodan_cpe" : "iou",
"1-ga_id" : "direct",
"1-ga_tag_id" : "direct",
"1-ip" : "direct",
"1-verification_id" : "direct",
"1-yandex_tag_id" : "direct",
"2-subnet" : "direct",
"3-cdn-domain" : "direct",
"3-cms" : "direct",
"3-css_classes" : "iou",
"3-header-nonstd-value" : "direct",
"3-header-server" : "direct",
"3-id_tags" : "iou",
"3-iframe_id_tags" : "iou",
"3-link_href" : "iou",
"3-meta_generic" : "iou",
"3-meta_social" : "direct",
"3-script_src" : "iou",
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
"2-urlscan_globalvariable": "iou",
"2-urlscan_cookies": "iou",
"2-urlscan_consolemessages": "iou",
"2-urlscan_asn": "direct",
"2-urlscan_domainsonpage": "iou",
"2-urlscan_urlssonpage" : "iou",
"2-urlscanhrefs" : "iou",
"2-techstack" : "iou"
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
    # "abs_difference_vs_threshold"
}
# todo add 'any in list" match


def find_matches(data, comparison=None, result_dir=None) -> pd.DataFrame:
    """
    This function iterates over the set of indicator types to calculate matches
    for each type. It then aggregates all found matches and returns them as a dataframe.
    * If no comparison dataset is provided, this function will do
    internal matching on the provided `data` dataset.
    * If result_dir is provided, intermediary results per-indicator type will be written out
    to the directory.
    """
    matches_per_feature = []
    if not comparison:
        comparison = data
    unique_indicator_types = data[INDICATOR_TYPE].unique()
    for indicator_type in unique_indicator_types:
        match_method = FEATURE_MATCHING.get(indicator_type)
        if not match_method:
            print(f"MISSING FEATURE MATCHING METHOD FOR: {indicator_type}")
            continue
        feature_df = data[data[INDICATOR_TYPE] == indicator_type]
        comparison_df = comparison[comparison[INDICATOR_TYPE] == indicator_type]
        #TODO FIX BAD MATCHES FOR SOME IOU FEATURES
        try:
            feature_matches = methods[match_method](
                feature_df=feature_df, feature=indicator_type, comparison_df=comparison_df
            )
            matches_per_feature.append(feature_matches)
            if result_dir:
                feature_matches.to_csv(
                    f"{result_dir}/{indicator_type}_matches.csv", index=False
                )
        except:
            print(f"Error matching feature: {indicator_type}")
    all_matches = pd.concat(matches_per_feature)
    return all_matches


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
        data1 = pd.read_csv(args.input_file)
        data2 = pd.read_csv(args.compare_file)
        result_file = result_file or f"{Path(args.input_file).stem}_{Path(args.compare_file).stem}_results.csv"
    else:
        data1 = pd.read_csv(args.input_file)
        data2 = None
        result_file = result_file or f"{Path(args.input_file).stem}_results.csv"
    matches = find_matches(data=data1, comparison=data2, result_dir=result_dir)
    print(f"Matches found: {matches.shape[0]}")
    print(
        f"Summary of matches:\n{matches.groupby('match_type')['match_value'].count()}"
    )
    matches.to_csv(result_file, index=False)
