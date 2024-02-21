import pytest
import pandas as pd
from unittest import mock

from modules.matcher import find_iou_matches, find_matches, main, DOMAIN, INDICATOR, INDICATOR_TYPE # , MATCH_TYPE, MATCH_VALUE


def test__find_direct_matches():
    raise NotImplementedError

@pytest.mark.parametrize(
        "feature_df,compare_df,expected_results",
        [
            (
                pd.DataFrame([{DOMAIN: "a", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [1, 2, 3]},
                                    {DOMAIN: "b", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [3, 4, 5]},
                                    {DOMAIN: "c", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [4, 5, 6]},]),
                pd.DataFrame([{DOMAIN: "a", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [1, 2, 3]},
                                    {DOMAIN: "b", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [3, 4, 5]},
                                    {DOMAIN: "c", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [4, 5, 6]},]),
                pd.DataFrame([{"domain_name_x": "a", "domain_name_y": "b", "match_type": "feature", "match_value": 0.2},
                          {"domain_name_x": "a", "domain_name_y": "c", "match_type": "feature", "match_value": 0.0},
                          {"domain_name_x": "b", "domain_name_y": "c", "match_type": "feature", "match_value": 0.5}])
            ),
            (
                pd.DataFrame([{DOMAIN: "a", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [1, 2, 3]},
                                    {DOMAIN: "b", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [3, 4, 5]},
                                    {DOMAIN: "c", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [4, 5, 6]},]),
                pd.DataFrame(columns=[DOMAIN, INDICATOR, INDICATOR_TYPE], 
                              data=[{DOMAIN: "a", INDICATOR_TYPE: INDICATOR_TYPE, INDICATOR: [7, 8, 9]}]),
                pd.DataFrame(columns=["domain_name_x", "domain_name_y", "match_type", "match_value"])
            )
        ]
)
def test__find_iou_matches_comparison(feature_df, compare_df, expected_results):
    results = find_iou_matches(feature_df=feature_df, comparison_df=compare_df, feature="feature", threshold=0)
    results = results.drop("matched_on", axis=1) # can't compare equality of sets
    pd.testing.assert_frame_equal(results, expected_results)

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

@pytest.mark.parametrize(
        "data,comparison,result_dir",
        [(pd.DataFrame([('D1', '1-cert-domain', 'a'), ('D1', '1-cert-domain', 'b'), ('D1', '3-id_tags', 'i'), ('D1', '3-id_tags', 'ii')], columns=[DOMAIN, INDICATOR_TYPE, INDICATOR]),
         None, None),
         (pd.DataFrame([('D1', '1-cert-domain', 'a'), ('D1', '1-cert-domain', 'b'), ('D1', '3-id_tags', 'i'), ('D1', '3-id_tags', 'ii')], columns=[DOMAIN, INDICATOR_TYPE, INDICATOR]),
         pd.DataFrame([('D2', '1-cert-domain', 'a'), ('D2', '1-cert-domain', 'c'), ('D2', '3-id_tags', 'i'), ('D2', '3-id_tags', 'iv')], columns=[DOMAIN, INDICATOR_TYPE, INDICATOR]), 
         None)]
)
def test__find_matches(data, comparison, result_dir):
    find_matches(data, comparison, result_dir)

@pytest.mark.parametrize(
    "input_file,compare_file,comparison_type,result_dir,output_file",
    [
        ('i_file', 'c_file', 'compare', 'r_dir', 'r_file'),
        ('i_file', 'c_file', 'pairwise', 'r_dir', 'r_file'),
        ('i_file', 'c_file', 'compare', 'r_dir', None),
        ('i_file', 'c_file', 'pairwise', 'r_dir', None),
        ('i_file', 'c_file', 'compare', None, 'r_file'),
        ('i_file', 'c_file', 'pairwise', None, 'r_file'),
        ('i_file', None, 'compare', 'r_dir', 'r_file'),
        ('i_file', None, 'pairwise', 'r_dir', 'r_file'),
    ]
)

@mock.patch('modules.matcher.find_matches')
@mock.patch('pandas.read_csv')
@mock.patch('modules.matcher.define_output_filename')
@mock.patch('modules.matcher.Path.mkdir')
def test__main(mock_mkdir, mock_define_output_filename, mock_read_csv, mock_find_matches, input_file,compare_file,comparison_type,result_dir,output_file):
    mock_define_output_filename.return_value = 'r_file'
    mock_read_csv.return_value = 'fake_data'
    main(input_file,compare_file,result_dir,output_file,comparison_type)
    if result_dir:
        mock_mkdir.assert_called_once_with(exist_ok=True)
    else:
        mock_mkdir.assert_not_called()
    if not output_file:
        mock_define_output_filename.assert_called_once_with(input_file, compare_file)
        output_file = 'r_file'
    else:
        mock_define_output_filename.assert_not_called()
    if comparison_type == 'compare' and compare_file:
        mock_find_matches.assert_called_with('fake_data', 'fake_data', result_dir=result_dir)
    else:
        mock_find_matches.assert_called_once_with('fake_data', result_dir=result_dir)
    