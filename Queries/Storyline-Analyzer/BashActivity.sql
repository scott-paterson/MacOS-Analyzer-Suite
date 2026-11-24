SELECT * FROM Storyline

-- Activity related to shell history/session files (.bash* / .zsh*).
-- The creating and modification of files within a User's shell history/session indicates commands were being run (commonly via Terminal.app).
WHERE ("Path" LIKE 'Users/%/.bash%' OR "Path" LIKE 'Users/%/.zsh%')

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC