# CKAN integration

If you have CKAN integration, this model will work with it.

1. Define the `que_job` table as per the [database integration guide](./database-integration.md).
2. Have a system administrator create a trigger function that tables can use, e.g.:

  ```bash
  D="$(cat <<EOF | jq -c .
  {
      "name": "append_to_verifiable_log",
      "or_replace": "true",
      "rettype": "trigger",
      "definition": "BEGIN ... copy from ./database-integration.md... END;"
  }
  EOF
  )"
  curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}" https://${CKAN_URL}/api/3/action/datastore_function_create | jq .
  ```

3. Enable trigger function for a dataset:

  ```bash
  D="$(cat <<EOF | jq -c .
  {
    "resource_id": "xxx", /* or: "resource": {"package_id": "xxx"}, */
    "fields": [
      {
        "id": "signed_certificate_timestamp",
        "type": "text"
      },
      ... other table fields ...
    ],
    "primary_key": "foo",
    "triggers": [{
      "function": "append_to_verifiable_log"
    }]
  }
  EOF
  )"
  curl -H "Content-Type: application/json" -d "$D" -H "Authorization: ${CKAN_KEY}" https://${CKAN_URL}/api/3/action/datastore_create | jq .
  ```

4. Ensure the [submit rows to logs](./submit-rows-to-logs.md) job is running.
