# Database integration

If you are using PostgreSQL, you can fairly easily integrate with an existing database table as follows:

## Prep table and trigger

We make use of the [github.com/bgentry/que-go](https://github.com/bgentry/que-go) library to process submitting rows to a verifiable log.

Prep by creating a `que_jobs` table:

```sql
CREATE TABLE IF NOT EXISTS que_jobs (
    priority    smallint    NOT NULL DEFAULT 100,
    run_at      timestamptz NOT NULL DEFAULT now(),
    job_id      bigserial   NOT NULL,
    job_class   text        NOT NULL,
    args        json        NOT NULL DEFAULT '[]'::json,
    error_count integer     NOT NULL DEFAULT 0,
    last_error  text,
    queue       text        NOT NULL DEFAULT '',
    CONSTRAINT que_jobs_pkey PRIMARY KEY (queue, priority, run_at, job_id)
);
```

Then define a trigger function:

```sql
CREATE OR REPLACE FUNCTION append_to_verifiable_log() RETURNS TRIGGER AS $append_to_verifiable_log$
BEGIN
    INSERT INTO que_jobs (queue, job_class, args)
    VALUES ('verifiable-logs', 'update_sct', json_build_object(
        'table', TG_TABLE_NAME,
        'data', NEW
    ));
    RETURN NEW;
END;
$append_to_verifiable_log$ LANGUAGE plpgsql;
```

## Test / demonstration

Now, you can do the following for any table that defines `_id` and `signed_certificate_timestamp`:

```sql
CREATE TABLE IF NOT EXISTS mytable (
    -- _id must be defined, be an integer, and be unique
    _id                           SERIAL NOT NULL,

    -- signed_certificate_timestamp must be allowed to be empty, and is populated by our tooling
    signed_certificate_timestamp  TEXT,

    -- any other fields you like. Note that fields beginning with "_" are excluded from processing
    foo                           TEXT,
    bar                           TIMESTAMPTZ DEFAULT NOW()
);

CREATE TRIGGER mytable_append_to_verifiable_log
    AFTER INSERT OR UPDATE OR DELETE ON mytable
    FOR EACH ROW EXECUTE PROCEDURE append_to_verifiable_log();
```

You can test verify the trigger by running an insert, for example:

```sql
INSERT INTO mytable(foo) VALUES('hi');
```

Then:

```sql
SELECT * FROM mytable;
 _id | signed_certificate_timestamp | foo |              bar              
-----+------------------------------+-----+-------------------------------
   1 |                              | hi  | 2018-03-20 00:21:22.239054+00
(1 row)
```

and:

```sql
SELECT * FROM que_jobs;
 priority |            run_at             | job_id | job_class  |                                                               args                                                                | error_count | last_error |      queue      
----------+-------------------------------+--------+------------+-----------------------------------------------------------------------------------------------------------------------------------+-------------+------------+-----------------
      100 | 2018-03-20 00:21:22.239054+00 |      1 | update_sct | {"table" : "mytable", "data" : {"_id":1,"signed_certificate_timestamp":null,"foo":"hi","bar":"2018-03-20T00:21:22.239054+00:00"}} |           0 |            | verifiable-logs
(1 row)
```

## Next

Done, this is now ready to be run with the [`submit-rows-to-logs`](./submit-rows-to-logs.md) tool.
