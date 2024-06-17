import argparse
import logging
from pathlib import Path
import pandas as pd

from modules.match import find_matches

def define_output_filename(file1, file2=None):
    if file2:
        return f"{Path(file1).stem}_{Path(file2).stem}_results.csv"
    return f"{Path(file1).stem}_results.csv"


def main(input_file, compare_file, output_file, comparison_type):
    data1 = pd.read_csv(input_file)
    if comparison_type == "compare" and compare_file:
        data2 = pd.read_csv(compare_file)
        matches: pd.DataFrame = find_matches(data1, data2)
    else:
        matches = find_matches(data1)
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
        default="pairwise",
    )
    parser.add_argument(
        "-cf",
        "--compare-file",
        type=str,
        help="file of indicators to compare against",
        required=False,
        default="./comparison_indicators.csv",
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )
    args = parser.parse_args()

    main(**vars(args))
