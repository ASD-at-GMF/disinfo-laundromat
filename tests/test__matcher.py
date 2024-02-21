import pandas as pd

from modules.matcher import find_iou_matches, DOMAIN, INDICATOR, INDICATOR_TYPE # , MATCH_TYPE, MATCH_VALUE

def test__find_direct_matches():
    raise NotImplementedError

def test__find_iou_matches_self():
    feature_df = pd.DataFrame(columns=[DOMAIN, INDICATOR, INDICATOR_TYPE], 
                              data=[{DOMAIN: "a", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [1, 2, 3]},
                                    {DOMAIN: "b", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [3, 4, 5]},
                                    {DOMAIN: "c", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [4, 5, 6]},])
    results = find_iou_matches(feature_df=feature_df, feature="feature", threshold=0)
    print(results)
    assert results.shape[0] == 3 # 3 pairs to compare
    assert set(results.columns) == {"domain_name_x", "domain_name_y", 'match_type', 'match_value', "matched_on"}

def test__find_iou_matches_comparison():
    feature_df = pd.DataFrame(columns=[DOMAIN, INDICATOR, INDICATOR_TYPE], 
                              data=[{DOMAIN: "a", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [1, 2, 3]},
                                    {DOMAIN: "b", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [3, 4, 5]},
                                    {DOMAIN: "c", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [4, 5, 6]},])
    results = find_iou_matches(feature_df=feature_df, comparison_df=feature_df, feature="feature", threshold=0)
    print(results)
    assert results.shape[0] == 3 # 3 pairs to compare
    assert set(results.columns) == {"domain_name_x", "domain_name_y", 'match_type', 'match_value', "matched_on"}
    # TODO: test that results are right!

def test__parse_whois_matches():
    raise NotImplementedError

def test__parse_certificate_matches():
    raise NotImplementedError

def test__any_in_list_matches():
    raise NotImplementedError

def test__dict_direct_match():
    raise NotImplementedError

def test__intersection():
    raise NotImplementedError

def test__abs_difference_vs_threshold():
    raise NotImplementedError

def test__find_matches():
    raise NotImplementedError