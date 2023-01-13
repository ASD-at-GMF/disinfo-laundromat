import sys
import pandas as pd
from pathlib import Path

DATA_DICTIONARY = "DataDictionary.csv"


def enrich_results(df):
    data_dict = pd.read_csv(DATA_DICTIONARY, sep=";")[["ID", "Tier"]].set_index("ID")
    whois_tiers = pd.Series(
        {
            "whois-registrar": 2,
            "whois-whois_server": 2,
            "whois-org": 1,
            "whois-city": 2,
            "whois-state": 2,
            "whois-country": 3,
        },
        name="Tier",
    ).to_frame()
    data_dict = pd.concat([data_dict, whois_tiers])
    enriched_df = pd.merge(
        df, data_dict, how="left", left_on="match_type", right_index=True
    )
    whois_tier = data_dict.loc["whois"]["Tier"]
    certificate_tier = data_dict.loc["certificate"]["Tier"]
    enriched_df.loc[
        enriched_df["match_type"].str.startswith("certificate"), "Tier"
    ] = certificate_tier
    return enriched_df


def to_gephi(enriched_df):
    enriched_df = enriched_df[enriched_df["Tier"] <= 1]
    aggregated = enriched_df.groupby(["domain_name_x", "domain_name_y"])[
        "match_value"
    ].count()
    aggregated = aggregated.reset_index()
    aggregated = aggregated.rename(
        columns={
            "domain_name_x": "Source",
            "domain_name_y": "Target",
            "match_value": "Weight",
        }
    )
    aggregated["Type"] = "Undirected"
    aggregated["Description"] = "Number of Tier 1 indicators"
    aggregated.index = aggregated.index.set_names(["Id"])
    aggregated.reset_index()
    return aggregated


if __name__ == "__main__":
    fname = sys.argv[1]
    df = pd.read_csv(fname)
    enriched_df = enrich_results(df)
    outname = Path(fname).parent / (Path(fname).stem + "_enriched.csv")
    print(outname)
    enriched_df.to_csv(outname)
    aggregated = to_gephi(enriched_df)
    aggregated.to_csv(Path(fname).parent / (Path(fname).stem + "_gephi.csv"))
