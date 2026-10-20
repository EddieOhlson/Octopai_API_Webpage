# Octopai API Webpage (Lineage Scan)

A small local web tool for Octopai / Cloudera Data Lineage tenants. Log in to any `<site>.octopai.com` and get a dashboard of the catalog, user activity, orphans and broken lineage, plus a keyword lineage scan with exportable reports.

It runs on your own computer. Your password goes only to the Octopai site you log in to and is never saved.

## What it does

- **Overview:** asset counts (column-level and cross-system), connections, and a breakdown by category (ETLs, Stored Procedures & SQL Files, DB Objects, Files & Analysis Services, Reports) with a subtotal per tool.
- **Orphans & Health:** assets with no connections, plus broken lineage found while lineage is downloaded (links to missing assets, count mismatches, failed requests).
- **Users & Activity:** user events with filters by event type and user, an events-per-day chart and CSV export. Needs an admin account.
- **Lineage Download:** downloads lineage graphs for your assets, saves them on your computer and exports JSON lines or CSV.
- **Keyword Scan:** finds columns by keyword and traces their sources or consumers. Searches the saved local files by default, or live from Octopai. Results can be exported as CSV or saved as PDF.

Catalog data and lineage are saved per site, so the next visit is fast.

## Requirements

- [Node.js](https://nodejs.org) 18 or newer. There are no other dependencies.

## Run it

```
cd api_webpage
npm start
```

Then open **http://localhost:5190**. Leave the terminal window open while you use it, and press Ctrl+C to stop. On macOS you can also double-click `start-api_webpage.command`.

After updating the files, stop the server (Ctrl+C) and run `npm start` again so it picks up the changes.

To use a different port: `PORT=5200 npm start`.

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
| `data/<site>.assets1.ndjson`, `assets2.ndjson` | Saved asset lists used by the local keyword scan |
| `data/exports/<site>/<run>.ndjson` | Lineage downloads |

Delete these files to start fresh. They can contain information about your customers' data catalogs, so do not share or commit them.

## Customizing

- **Category rules:** edit `public/categories.js` if a tool lands in the wrong category. Reload the page afterwards. No rebuild is needed.

## How it works

`server.js` is a zero-dependency Node server. It serves the page from `public/`, forwards API calls from `/octopai/*` to `https://<site>.octopai.com` (only hosts ending in `.octopai.com`), and reads and writes the files in `data/`. The page (`public/app.js`) uses the Octopai API: Login, `assets/query` (paged with limit and offset), `lineage` and `UserEvents`.

## Troubleshooting

- **"rejected this username or password":** check that the account exists on that site and is not SSO-only or locked.
- **"X-Octopai-Host must be <tenant>.octopai.com":** the running server is an old version. Stop it and run `npm start` again.
- **Large catalogs load slowly.** Millions of column-level assets can take several minutes on the first load.
