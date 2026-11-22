# Compare reports

**Compare reports** (linked from the upload page and every results page) shows which IOCs and
vulnerabilities appear in more than one saved report, and in how many networks.

1. Tick the reports to compare. The list holds every run saved by this upload page, newest first.
   To include a report saved somewhere else, open it on the upload page first (**Open report**).
2. Check each report's **Network**. Reports with the same network count as one network.
3. Leave **Look for every IOC matched in any chosen report in all of them** ticked, and optionally
   add an IOC CSV, to search each report's saved data again: an indicator learned after a report
   was made, or matched in only one report, is found in the others too.
4. Click **Compare**. The comparison has IOC, Vulnerability and Report tabs. Each row shows how
   many reports, networks and hosts it was seen in, with one square per report, oldest first:
   filled when the analysis found it, striped when only the new search did. Click a row for the
   hosts in each report.

**Open all networks in the Explorer** draws every compared report on one map, each network as its
own labelled cluster, with outside addresses merged onto the arc overhead. Hover a host to see what
it shares with other reports; its card links to that report's own Explorer.

Comparisons are saved in the data folder under `comparisons/<time>/` (`ioc_overlap.csv`,
`vulnerability_overlap.csv`, `comparison.json`, and the map). The reports themselves are not
changed. From the command line:

```sh
python3 -m vulnflow compare vulnflow_runs/ -o compare_out --ioc-csv new_iocs.csv
python3 -m vulnflow compare nov/out dec/out --network "dec/out=Plant 3"   # set a report's network
```

Vulnerabilities are matched by Nessus plugin and IOCs by indicator, never by internal address,
since the same private address in two networks is two different machines. See
[Comparing reports](../METHODS.md#comparing-reports) for the rules.

## Several sites in one folder

One analysis treats everything in a folder as one network, so the same private address at two
sites becomes one host. To keep sites apart, give each its own folder (one folder per company, a folder per site inside it) and add a `sites.csv` next to
the company folders:

```csv
folder,name,network,description
corvane/hq,Corvane HQ,Corvane,Head office
corvane/phoenix,Corvane Phoenix plant,Corvane,
ridgeline/denver,Ridgeline Denver office,Ridgeline,
```

The button then reads **Analyze 3 sites and compare**: each site gets its own report, and their
comparison opens when they are done. Only `folder` is required; `name` defaults to the site folder
and `network` to the company folder. An IOC CSV, `network_map.csv` or `known_scanners.csv` next to
`sites.csv` applies to every site. From the command line:

```sh
python3 -m vulnflow analyze-sites /path/to/folder
```
