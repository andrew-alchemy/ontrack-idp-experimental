--
-- this is the DDL required to support IDP's serevr side storage
--
-- https://alchemysystems.atlassian.net/wiki/spaces/~andrew.tomlinson/pages/70090757/Shibboleth+IDP
-- https://wiki.shibboleth.net/confluence/display/IDP30/StorageConfiguration
--
CREATE TABLE dbo.StorageRecords ( 
	context varchar(255) NOT NULL, 
	id varchar(255) NOT NULL, 
	expires bigint DEFAULT NULL, 
	value nvarchar(max) NOT NULL, 
	version bigint NOT NULL,
PRIMARY KEY CLUSTERED (context,id)
);