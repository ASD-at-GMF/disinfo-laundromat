import pytest
import pandas as pd
from unittest import mock

from modules.matcher import (
    any_in_list_match,
    direct_match,
    iou_match,
    find_matches,
    main,
    DOMAIN,
    INDICATOR,
    INDICATOR_TYPE,
    MATCH_VALUE,
)

def feature_group_as_list_1():
    return pd.DataFrame(
                [
                    {DOMAIN: "a", INDICATOR: [1, 2, 3]},
                    {DOMAIN: "b", INDICATOR: [3, 4, 5]},
                    {DOMAIN: "c", INDICATOR: [4, 5, 6]},
                ]
            )

def feature_group_as_list_str_1():
    return pd.DataFrame(
                [
                    {DOMAIN: "a", INDICATOR: "[1, 2, 3]"},
                    {DOMAIN: "b", INDICATOR: "[3, 4, 5]"},
                    {DOMAIN: "c", INDICATOR: "[4, 5, 6]"},
                ]
            )

def feature_group_as_list_str_2():
    return pd.DataFrame(
                columns=[DOMAIN, INDICATOR],
                data=[
                    {DOMAIN: "a", INDICATOR: "[7, 8, 9]"}
                ],
            )

def feature_group_as_string_1():
    return pd.DataFrame(
                [
                    {DOMAIN: "a", INDICATOR: "foo"},
                    {DOMAIN: "a", INDICATOR: "bar"},
                    {DOMAIN: "b", INDICATOR: "bar"},
                    {DOMAIN: "b", INDICATOR: "fake"},
                    {DOMAIN: "b", INDICATOR: "phrase"},
                    {DOMAIN: "c", INDICATOR: "fake"},
                    {DOMAIN: "c", INDICATOR: "phrase"},
                ]
            )

@pytest.mark.parametrize(
    "feature_df,compare_df,expected_results",
    [
        (
            pd.DataFrame(
                [
                    {DOMAIN: "foo", INDICATOR: "abc"},
                    {DOMAIN: "bar", INDICATOR: "123"},
                ]
            ),
            pd.DataFrame(
                [
                    {DOMAIN: "foo", INDICATOR: "abc"},
                    {DOMAIN: "foo2", INDICATOR: "abc"},
                ]
            ),
            pd.DataFrame(
                [
                    {
                        "domain_name_x": "foo",
                        MATCH_VALUE: "abc",
                        "domain_name_y": "foo2",
                    },
                ]
            ),
        ),
        (
            pd.DataFrame(
                [
                    {DOMAIN: "foo",  INDICATOR: "abc"},
                    {DOMAIN: "bar", INDICATOR: "123"},
                ]
            ),
            pd.DataFrame(
                [{DOMAIN: "foo2", INDICATOR: "nope"}]
            ),
            pd.DataFrame(
                [], columns=["domain_name_x", MATCH_VALUE, "domain_name_y"]
            ),
        ),
    ],
)
def test__direct_match(feature_df, compare_df, expected_results):
    matches = direct_match(feature_df, compare_df)
    pd.testing.assert_frame_equal(matches, expected_results, check_index_type=False)


@pytest.mark.parametrize(
    "feature_df,compare_df,expected_results",
    [
        pytest.param(
            feature_group_as_list_str_1(),
            feature_group_as_list_str_1(),
            pd.DataFrame(
                [
                    {
                        "domain_name_x": "b",
                        "domain_name_y": "c",
                        "match_value": 0.5,
                    },
                ]
            ),
        id="listlike strings, same values"),
        pytest.param(
            feature_group_as_list_1(),
            feature_group_as_list_str_1(),
            pd.DataFrame(
                [
                    {
                        "domain_name_x": "b",
                        "domain_name_y": "c",
                        "match_value": 0.5,
                    },
                ]
            ),
        id="one list, one listlike string, same values"),
        pytest.param(
            feature_group_as_string_1(),
            feature_group_as_string_1(),
            pd.DataFrame(
                [
                    {
                        "domain_name_x": "b",
                        "domain_name_y": "c",
                        "match_value": 0.667,
                    },
                ]
            ),
        id="two set-like strings, different values"),
        pytest.param(
            feature_group_as_list_str_1(),
            feature_group_as_list_str_2(),
            pd.DataFrame(
                columns=["domain_name_x", "domain_name_y", "match_value"]
            ),
        id="two listlike strings, different values"),
    ],
)
def test__iou_match(feature_df, compare_df, expected_results):
    results = iou_match(
        feature_df=feature_df, comparison_df=compare_df, threshold=0.5
    )
    pd.testing.assert_frame_equal(results, expected_results, check_index_type=False)


def test__parse_whois_matches():
    raise NotImplementedError


def test__parse_certificate_matches():
    raise NotImplementedError

@pytest.mark.parametrize(
    "feature_df,compare_df,expected_results",
    [
        (
            feature_group_as_list_str_1(),
            feature_group_as_list_str_1(),
            pd.DataFrame(
                [
                    {
                        "domain_name_x": "a",
                        "domain_name_y": "b",
                        "match_value": 1,
                    },
                    {
                        "domain_name_x": "b",
                        "domain_name_y": "c",
                        "match_value": 2,
                    },
                ]
            )
        ),
        (
            feature_group_as_string_1(),
            feature_group_as_string_1(),
            pd.DataFrame(
                [
                    {
                        "domain_name_x": "a",
                        "domain_name_y": "b",
                        "match_value": 1,
                    },
                    {
                        "domain_name_x": "b",
                        "domain_name_y": "c",
                        "match_value": 2,
                    },
                ]
            )
        ),
        (
            feature_group_as_list_str_1(),
            feature_group_as_list_str_2(),
            pd.DataFrame(
                columns=["domain_name_x", "domain_name_y", "match_value"],
                data=[]
            )
        ),
    ]
)
def test__any_in_list_match(feature_df, compare_df, expected_results):
    results = any_in_list_match(feature_df, compare_df)
    pd.testing.assert_frame_equal(results.reset_index(drop=True), expected_results.reset_index(drop=True), check_index_type=False)


def test__dict_direct_match():
    raise NotImplementedError


def test__intersection():
    raise NotImplementedError


def test__abs_difference_vs_threshold():
    raise NotImplementedError


@pytest.mark.parametrize(
    "data,comparison",
    [
        (
            pd.DataFrame(
                [
                    ("D1", "1-cert-domain", "a"),
                    ("D1", "1-cert-domain", "b"),
                    ("D1", "3-id_tags", "i"),
                    ("D1", "3-id_tags", "ii"),
                ],
                columns=[DOMAIN, INDICATOR_TYPE, INDICATOR],
            ),
            None,
        ),
        (
            pd.DataFrame(
                [
                    ("D1", "1-cert-domain", "a"),
                    ("D1", "1-cert-domain", "b"),
                    ("D1", "3-id_tags", "i"),
                    ("D1", "3-id_tags", "ii"),
                ],
                columns=[DOMAIN, INDICATOR_TYPE, INDICATOR],
            ),
            pd.DataFrame(
                [
                    ("D2", "1-cert-domain", "a"),
                    ("D2", "1-cert-domain", "c"),
                    ("D2", "3-id_tags", "i"),
                    ("D2", "3-id_tags", "iv"),
                ],
                columns=[DOMAIN, INDICATOR_TYPE, INDICATOR],
            ),
        ),
    ],
)
def test__find_matches(data, comparison):
    find_matches(data, comparison)


@pytest.mark.parametrize(
    "input_file,compare_file,comparison_type,output_file",
    [
        ("i_file", "c_file", "compare", "r_file"),
        ("i_file", "c_file", "pairwise", "r_file"),
        ("i_file", "c_file", "compare", None),
        ("i_file", "c_file", "pairwise", None),
        ("i_file", "c_file", "compare", "r_file"),
        ("i_file", "c_file", "pairwise", "r_file"),
        ("i_file", None, "compare", "r_file"),
        ("i_file", None, "pairwise", "r_file"),
    ],
)
@mock.patch("modules.matcher.find_matches")
@mock.patch("pandas.read_csv")
@mock.patch("modules.matcher.define_output_filename")
@mock.patch("modules.matcher.Path.mkdir")
def test__main(
    mock_mkdir,
    mock_define_output_filename,
    mock_read_csv,
    mock_find_matches,
    input_file,
    compare_file,
    comparison_type,
    output_file,
):
    mock_define_output_filename.return_value = "r_file"
    mock_read_csv.return_value = "fake_data"
    main(input_file, compare_file, output_file, comparison_type)
    if not output_file:
        mock_define_output_filename.assert_called_once_with(input_file, compare_file)
        output_file = "r_file"
    else:
        mock_define_output_filename.assert_not_called()
    if comparison_type == "compare" and compare_file:
        mock_find_matches.assert_called_with("fake_data", "fake_data" )
    else:
        mock_find_matches.assert_called_once_with("fake_data")
