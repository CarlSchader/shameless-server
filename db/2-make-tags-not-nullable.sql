-- logs.tag is a nullable string. I need to make i not nullable and replace all null values with an empty string. this is postgres

UPDATE logs SET tag = '' WHERE tag IS NULL;
ALTER TABLE logs ALTER COLUMN tag SET NOT NULL;
