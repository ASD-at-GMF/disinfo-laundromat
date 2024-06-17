import os
import argparse
import logging
from pathlib import Path

import pandas as pd
from modules.crawl import crawl, get_domain_name



def write_domain_indicators(domain, indicators, output_file):
    attribution_table = pd.DataFrame(
        columns=["indicator_type", "indicator_content"],
        data=(indicator.to_dict() for indicator in indicators),
    )
    attribution_table['domain_name'] = domain
    # this is done so if anything bad happens to break the script, we still get partial results
    # this approach also keeps the indicators list from becoming huge and slowing down
    if Path(output_file).exists():
        attribution_table.to_csv(
            output_file,
            index=False,
            mode="a",
            encoding="utf-8",
            header=False,
        )
    else:
        attribution_table.to_csv(
            output_file,
            index=False,
            mode="w",
            encoding="utf-8",
            header=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Match indicators across sites.", add_help=False
    )
    parser.add_argument(
        "-f",
        "--input-file",
        type=str,
        help="file containing list of domains",
        required=False,
        default=os.path.join(".", "sites_of_concern.csv"),
    )
    parser.add_argument(
        "-c", "--domain-column", type=str, required=False, default="Domain"
    )
    # option to run urlscan
    parser.add_argument("-u", "--run-urlscan", type=bool, required=False, default=False)

    parser.add_argument(
        "-o",
        "--output-file",
        type=str,
        help="file to save final list of match results",
        required=False,
        default=os.path.join(".", "indicators_output.csv"),
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )

    args = parser.parse_args()
    domain_col = args.domain_column
    output_file = args.output_file
    run_urlscan = args.run_urlscan
    input_data = pd.read_csv(args.input_file)
    domains = input_data[domain_col]
    for domain in domains:
        try:
            print(f"Processing {domain}")
            domain_name = get_domain_name(domain)
            indicators = crawl(domain, run_urlscan=run_urlscan)
            write_domain_indicators(domain_name, indicators, output_file=output_file)
        except Exception as e:
            logging.error(f"Failing error on {domain}. See traceback below. Soldiering on...")
            logging.error(e, exc_info=True)