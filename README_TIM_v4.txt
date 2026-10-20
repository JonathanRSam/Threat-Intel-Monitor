Threat Intel Monitor v4
=======================

What it does
------------
This script pulls threat intel from RSS and JSON sources and creates a daily Excel file.

The Excel file has three tabs:

1. CRITICAL - Full Review
   Items that may need same-day action or exposure validation.

2. REVIEW - Analyst Check
   Items worth checking manually.

3. LOW - Archive
   Awareness-only items with no immediate action.


Setup
-----
Install Python 3.10 or newer.

Then install the required packages:

    pip install -r requirements_TIM_v4.txt

If you are not using the requirements file, install the packages manually:

    pip install feedparser pandas requests beautifulsoup4 openpyxl


How to run
----------
Keep this file in the TIM v4 folder:

    threat_intel_monitor_v4.py

Run it using:

    python threat_intel_monitor_v4.py

The output Excel file will be created in the same folder.

Example output filename:

    threat_intel_2026-07-10.xlsx

IMPORTANT: Close the Excel file before rerunning the script. If the Excel file is open, the script may not be able to update it.


Runtime files
-------------
The script creates a folder called runtime_logs.

This folder contains:

- monitor_run_activity.log
  Run logs, source warnings, and summary counts.

- last_run_state.json
  The last successful run time.

- seen_items.json
  Seen and alerted item tracking.

- run_history.jsonl
  Basic run history.


Run logic
---------
First run:

    Checks the previous 24 hours.

Later runs:

    Checks from the last successful run time.
    Catch-up is capped at 72 hours.

If zero records are collected, the script does not update the Excel file or state files.



Notes
-----
- IOCs, CVEs, and affected products should still be validated before taking action.
- Most tuning can be done in the Company profile, source, and keyword sections near the top of the script.
