SELECT * FROM Storyline

-- Description: Sudo-related artifacts.
--
-- Important: Aftermath Storyline does NOT reliably capture "sudo was executed" events.
-- This query searches for common filesystem artifacts that may be touched by sudo usage/configuration,
-- plus installer script logs that literally contain "sudo ...".
WHERE (
    -- sudo timestamp files (classic artifact)
    "Path" LIKE '%private/var/db/sudo/%'
    OR "Path" LIKE '%/var/db/sudo/%'

    -- sudo configuration edits
    OR "Path" LIKE '%/etc/sudoers%'
    OR "Path" LIKE '%private/etc/sudoers%'
    OR "Path" LIKE '%/etc/sudoers.d/%'
    OR "Path" LIKE '%private/etc/sudoers.d/%'

    -- installer/other logs that contain a sudo command string (exclude browser history noise below)
    OR (
        TRIM(Type) = 'INSTALL'
        AND (COALESCE("Path",'') LIKE '% sudo %' OR COALESCE("Other",'') LIKE '% sudo %')
    )
)
AND TRIM(Type) NOT LIKE '%history%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC