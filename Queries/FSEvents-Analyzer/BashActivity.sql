SELECT * FROM FSEventsParser

-- Activity related to shell history/session files (.bash* / .zsh*).
-- The creating and modification of files within a User's shell history/session indicates commands were being run (commonly via Terminal.app).
WHERE ("Full Path" LIKE 'Users/%/.bash%' OR "Full Path" LIKE 'Users/%/.zsh%')

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC