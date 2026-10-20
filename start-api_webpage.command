#!/bin/bash
cd "$(dirname "$0")" || exit 1
command -v node >/dev/null || { echo "Install Node first: brew install node"; read -r -p "Press Enter..."; exit 1; }
(sleep 1; open "http://localhost:5190") &
node server.js
