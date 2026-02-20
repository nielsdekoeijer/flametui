# Source - https://stackoverflow.com/a/70952378
# Posted by ceving, modified by community. See post 'Timeline' for change history
# Retrieved 2026-02-20, License - CC BY-SA 4.0

#! /bin/bash

find /proc -maxdepth 1 -type d -regex '/proc/[0-9]+' -printf '%P\n' |
  {
    while read -r pid; do
      if [[ -d /proc/$pid ]]; then
        printf '%d:' "$pid"
        find /proc/"$pid"/fd -type l -printf ' %P' 2>/dev/null
        printf '\n'
      fi
    done
  }

