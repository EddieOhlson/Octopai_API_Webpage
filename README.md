# Octopai API Webpage (Lineage Scan)

A small local web tool for Octopai / Cloudera Data Lineage tenants. Log in to any `<site>.octopai.com` and get a dashboard of the catalog, user activity, orphans and broken lineage, plus a keyword lineage scan with exportable reports.

It runs on your own computer. Your password goes only to the Octopai site you log in to and is never saved.

## What it does

- **Lineage stats (top of Overview):** five cards for the selected asset type:
  - **High Impact Objects:** assets with 4 or more lineage links (in plus out).
  - **Most Connected Object:** the asset with the most links, with its in and out counts. Click it to open it in the Lineage Explorer.
  - **Cross-System Objects:** cross-system assets split into ETL, DB and Reports.
  - **Pipeline Depth:** for assets with downloaded downstream lineage, how many hops their longest chain has (average and spread).
  - **Lineage Health:** the share of assets with at least one lineage link, and the number of orphans.

  High Impact, Most Connected and Lineage Health use the link counts Octopai sends with every asset, so they cover all assets, not a sample. Pipeline Depth needs downstream lineage from the Lineage Download tab. To change the high-impact threshold, edit `HIGH_IMPACT_DEGREE` in `public/app.js`.
- **Overview:** asset counts (column-level and cross-system), connections, and a breakdown by category (ETLs, Stored Procedures & SQL Files, DB Objects, Files & Analysis Services, Reports) with a subtotal per tool.
- **Lineage Explorer:** three columns like Octopai's Cross System Lineage Dashboard (ETLs, Stored Procedures & SQL Files · DB Objects, Files & Analysis Services · Reports), with a search box. Click any asset for an **impact analysis**: what it gets data from (upstream), everything that would be affected if it changed (downstream), how many reports that includes, and a full list you can download as CSV. Click a related asset to jump to its own analysis. Saved lineage is used when there is some; otherwise it is fetched from Octopai and saved for next time.
- **Orphans & Health:** assets with no connections, plus broken lineage found while lineage is downloaded (links to missing assets, count mismatches, failed requests).
- **Users & Activity:** user events with filters by event type and user, an events-per-day chart and CSV export. Needs an admin account.
- **Lineage Download:** downloads lineage graphs for your assets, saves them on your computer and exports JSON lines or CSV.
- **Catalog Health:** for the selected asset type and sources:
  - **Breakdown by schema:** assets, orphans and cleanup candidates per schema.
  - **Cleanup candidates:** Oracle recycle-bin objects (`BIN$...`), backup copies (`BKP_`, `_BKP_<date>`), test or temporary objects (`_TEST`, `TEMP_`) and dated copies, with whether each one still has lineage links.
  - **Same name in several schemas:** packages, tables and views whose name appears in more than one schema, which can be copies that have drifted apart.
  - **Report coverage:** which DB objects feed at least one report, based on downloaded downstream lineage, overall and per schema.
  
  Each section can be exported as CSV.
- **Source filter:** the **Sources** button works like the metadata source picker in Octopai. Uncheck ETL, DB or report connections to leave them out of the KPIs, Overview, Orphans & Health, Catalog Health and the lineage download. The choice is remembered per site in this browser.
- **Keyword Scan:** finds columns by keyword and traces their sources or consumers. Searches the saved local files by default, or live from Octopai. Results can be exported as CSV or saved as PDF.

Catalog data and lineage are saved per site, so the next visit is fast. At login the app reads assets and user events from the saved files if they are less than 10 days old, instead of downloading them from Octopai again. Click **Reload assets and events** to refresh them from Octopai at any time. To change the 10 days, edit `SAVED_MAX_AGE_HOURS` near the top of `public/app.js` (`Infinity` = never reload automatically, `0` = always reload at login).

## Requirements

- [Node.js](https://nodejs.org) 18 or newer. There are no other dependencies.

## Run it

```
cd api_webpage
npm start
```

Then open **http://localhost:5191**. Leave the terminal window open while you use it, and press Ctrl+C to stop. On macOS you can also double-click `start-api_webpage.command`.

To use a different port: `PORT=5200 npm start`.

## Updating

1. Get the new files: `git pull` (or Sync Changes in VS Code).
2. Restart the server: press Ctrl+C in the terminal where it runs, then `npm start`. The server only picks up changes to `server.js` when it starts.
3. Hard-refresh the page in the browser: **Cmd+Shift+R** on a Mac, **Ctrl+Shift+R** (or Ctrl+F5) on Windows. A normal reload can keep using the old page files from the browser cache.
4. Log in again.

Updating does not touch the `data/` folder, so your saved catalog, user events and lineage are kept. Occasionally an update changes what is saved; the first login after such an update downloads the assets from Octopai once, and later logins use the saved files again.

## Using it

1. Enter the site name, for example `demo` for `demo.octopai.com`. For regional sites, enter `demo.eu` for `demo.eu.octopai.com`.
2. Log in with your Octopai username and password.
3. The catalog and user events load first. Use the tabs to explore, and the Cross-system / Column-level switch to change which asset type the breakdown and orphans describe.
4. Optional: open **Lineage Download** to download lineage. This finds confirmed orphans and broken links, and it feeds the local keyword scan.
5. Open **Keyword Scan**, enter keywords such as `email, ssn`, choose Source or Consumer columns, and scan. If some columns have no saved lineage, use the "Fetch lineage for the missing columns" button.

If your token expires during a long run, a prompt asks for your password again and the run continues without losing results.

## Where data is stored

Everything is saved in the `data/` folder next to `server.js`. It is excluded from git.

| File | Contents |
| --- | --- |
| `data/<site>.catalog.json` | Catalog summary and 24-hour lineage cache |
| `data/<site>.assets1.ndjson.gz`, `assets2.ndjson.gz` | Saved asset lists (compressed), used at login and by the local keyword scan. Large catalogs are fine: 1 million assets take about 13 MB. While they are being saved the status bar says "Saving … keep this page open". |
| `data/<site>.events.json` | Saved user events |
| `data/exports/<site>/<run>.ndjson` | Lineage downloads |
| `data/exports/<site>/explorer-<date>.ndjson` | Lineage fetched by the Lineage Explorer |

Delete these files to start fresh. They can contain information about your customers' data catalogs, so do not share or commit them.

## Customizing

- **Category rules:** edit `public/categories.js` if a tool lands in the wrong category. Reload the page afterwards. No rebuild is needed.
- **Catalog Health rules:** edit `public/health-rules.js` to change which names count as cleanup candidates, or to tune the same-name check. Reload the page afterwards.
- **Report coverage** counts a downstream node as a report when `categories.js` puts it in Reports, Analytics & Information Consumers. For it to work, download lineage with the **Downstream** direction for the asset type you want to check.

## How it works

`server.js` is a zero-dependency Node server. It serves the page from `public/`, forwards API calls from `/octopai/*` to `https://<site>.octopai.com` (only hosts ending in `.octopai.com`), and reads and writes the files in `data/`. The page (`public/app.js`) uses the Octopai API: Login, `assets/query` (paged with limit and offset), `lineage` and `UserEvents`.

## Troubleshooting

- **"rejected this username or password":** check that the account exists on that site and is not SSO-only or locked.
- **"X-Octopai-Host must be <tenant>.octopai.com":** the running server is an old version. Stop it and run `npm start` again.
- **Large catalogs load slowly.** Millions of column-level assets can take several minutes on the first load.
