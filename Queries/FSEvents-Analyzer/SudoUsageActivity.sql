SELECT * FROM FSEventsParser

-- Description: Sudo-related artifacts.
--
-- FSEvents capture filesystem activity, not command execution. This query searches for paths commonly
-- touched by sudo usage/configuration.
WHERE (
    "Full Path" LIKE '%private/var/db/sudo/%'
    OR "Full Path" LIKE '%/var/db/sudo/%'
    OR "Full Path" LIKE '%/etc/sudoers%'
    OR "Full Path" LIKE '%private/etc/sudoers%'
    OR "Full Path" LIKE '%/etc/sudoers.d/%'
    OR "Full Path" LIKE '%private/etc/sudoers.d/%'
)

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC