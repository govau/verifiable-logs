# Working with a log

(URL for UI: <http://localhost:8080/dataset/mytable/>)

Let's start by adding a few more entries to our table from before, so back in our `psql` prompt:

```sql
INSERT INTO mytable(foo) VALUES ('a'), ('b'), ('c'), ('d'), ('e'), ('f'), ('g');
```

Verify that a few seconds later (default wait between empty jobs is 5 seconds), that the SCTs are populated:

```sql
SELECT * FROM mytable;
 _id |                                                                   signed_certificate_timestamp                                                                   | foo |              bar              
-----+------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----+-------------------------------
   1 | AP3jBbYBP3zNLI6wFo39xSbEK2G11ofrbZ4YHjo3hVxxAAABYkHtkSYAAAQDAEgwRgIhAJGl3ZuPLM/MJTu4Vhy6zs43I6cExWCzBU9YVoONtEMtAiEA5hn4AckRnntPvGrhSZ7ZEyRt7ZjuaLdBonx9a4oyk0I= | hi  | 2018-03-20 05:40:35.780239+00
   3 | AP3jBbYBP3zNLI6wFo39xSbEK2G11ofrbZ4YHjo3hVxxAAABYkHy6ZQAAAQDAEcwRQIhALlnIKRhK6OVWoSoBZcsryeNM6nyFP1ot0IIeW5RBxgcAiACAqAfo60/O9scd48APKKSCqYveRhVJ8CFJlPQxXXuWw== | b   | 2018-03-20 05:47:42.909064+00
   5 | AP3jBbYBP3zNLI6wFo39xSbEK2G11ofrbZ4YHjo3hVxxAAABYkHy6ZYAAAQDAEYwRAIgTZ3rk8gnWdEKQyTcGm+2ak9l9Qh8NsAO9NDiFt4Wr5YCIAcawaIU5Vh8sLjWNYUK8Q6mS3L1brvObk3Fr5Pk+Gj8     | d   | 2018-03-20 05:47:42.909064+00
   2 | AP3jBbYBP3zNLI6wFo39xSbEK2G11ofrbZ4YHjo3hVxxAAABYkHy6ZkAAAQDAEcwRQIgOz1PNLAjhs/VTKUi+aW63n75cflAssPV/XjqNCo3xyACIQDnpl4FNn9K8i8Q1854w+HDWU9GbAOasMQqRABdihz1Xg== | a   | 2018-03-20 05:47:42.909064+00
   4 | AP3jBbYBP3zNLI6wFo39xSbEK2G11ofrbZ4YHjo3hVxxAAABYkHy6aMAAAQDAEcwRQIgePiDbc/orfNm5lwOGko88XiTwbEnUuIMBB6Sowz6yvkCIQDj+gPdGnZqjPxlv8do3OEAoHZV3pqi4TokgNx5WEBx7Q== | c   | 2018-03-20 05:47:42.909064+00
   7 | AP3jBbYBP3zNLI6wFo39xSbEK2G11ofrbZ4YHjo3hVxxAAABYkHy6ccAAAQDAEcwRQIhAKyWff8EyBIEtHNxzxxa0avsphM/K2mWxqZmdLjvb6bfAiBZH+OyWIqma+eztbCaXTMaXgfFZIqz9zRqfyOWJX4Lrg== | f   | 2018-03-20 05:47:42.909064+00
   6 | AP3jBbYBP3zNLI6wFo39xSbEK2G11ofrbZ4YHjo3hVxxAAABYkHy6bQAAAQDAEYwRAIgVn/wPr5afQclMaOINmJchUAjzhSLJhiuIOqN75pkxmICIE1OP0BsjYA2qKgQR/GpBFlMaLxgidg2TL/Uzc6ed3P3     | e   | 2018-03-20 05:47:42.909064+00
   8 | AP3jBbYBP3zNLI6wFo39xSbEK2G11ofrbZ4YHjo3hVxxAAABYkHy6d4AAAQDAEcwRQIgd5azDVpty5RMXwSInmBktdrkJdU/QguVF0T4oU3hxn8CIQDta2Q8dbrgv8Xw9p84P0n5ebBvkT0qdy0AX2xSg1VHdg== | g   | 2018-03-20 05:47:42.909064+00
(8 rows)
```

## Log metadata

```bash
# This returns the public key that the log uses to sign tree heads and signed certificate timestamps.
# It will never change for the lifetime of a log, and in our implementation is unique per table.
curl http://localhost:8080/dataset/mytable/ct/v1/metadata | jq .
{
  "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE05Z6xXgjASHq7qmXZQR4c9alkBY0C6oxPdhmS/j2kSlDEq3yuAhe9FhPsJnBIkvXW6T2Zt8Z6NdlFRc6krXoQg=="
}

# Fetch the current signed tree head
curl http://localhost:8080/dataset/mytable/ct/v1/get-sth | jq .
{
  "tree_size": 8,
  "timestamp": 1521525014940,
  "sha256_root_hash": "XK4YxkYIM/g55joQ2TLJy2UYfwBuRsyBI1Xf0mrLJ1w=",
  "tree_head_signature": "BAMASDBGAiEA0alyBdmjDDrPFboBIswaFyS/0Jc2AgSI8LaQY6Wrc9gCIQDbtJX9kCi7zOV3UoYM3vrMzFkY0dZecljt7rs1tS7dYw=="
}

# Fetch the entries from the log
curl "http://localhost:8080/dataset/mytable/ct/v1/get-entries?start=0&end=7" | jq .
{
  "entries": [
    {
      "leaf_input": "AAAAAAFiQe2RJoAB4hScjyAjLHioJyymTwcW1AfGrLLaMBVh1LdaZvPdT2cAAA==",
      "extra_data": "eyJiYXIiOiIyMDE4LTAzLTIwVDA1OjQwOjM1Ljc4MDIzOSswMDowMCIsImZvbyI6ImhpIn0="
    },
    {
      "leaf_input": "AAAAAAFiQfLplIABdaWHo8hTsDFsOqnPEcIG9ZFf1drUzC+mx4xJve+7mBwAAA==",
      "extra_data": "eyJiYXIiOiIyMDE4LTAzLTIwVDA1OjQ3OjQyLjkwOTA2NCswMDowMCIsImZvbyI6ImIifQ=="
    },
    {
      "leaf_input": "AAAAAAFiQfLploABXVCxOionLgrW5KuxrDrdJ76ZfukoEfp6r+hoCexTC0sAAA==",
      "extra_data": "eyJiYXIiOiIyMDE4LTAzLTIwVDA1OjQ3OjQyLjkwOTA2NCswMDowMCIsImZvbyI6ImQifQ=="
    },
    {
      "leaf_input": "AAAAAAFiQfLpo4ABFcnx1xuGCzXTlkpXd56THNfxnkXergpvr7NpzQ3jUdgAAA==",
      "extra_data": "eyJiYXIiOiIyMDE4LTAzLTIwVDA1OjQ3OjQyLjkwOTA2NCswMDowMCIsImZvbyI6ImMifQ=="
    },
    {
      "leaf_input": "AAAAAAFiQfLpmYABz0Sz8r1xHURWYAP35ieaxi/WhW9oDMJDLbqGMq66REgAAA==",
      "extra_data": "eyJiYXIiOiIyMDE4LTAzLTIwVDA1OjQ3OjQyLjkwOTA2NCswMDowMCIsImZvbyI6ImEifQ=="
    },
    {
      "leaf_input": "AAAAAAFiQfLpx4ABjhts3+LiRtupAnhwRBpOzuXaPo98K+dk1s0lAbayOB0AAA==",
      "extra_data": "eyJiYXIiOiIyMDE4LTAzLTIwVDA1OjQ3OjQyLjkwOTA2NCswMDowMCIsImZvbyI6ImYifQ=="
    },
    {
      "leaf_input": "AAAAAAFiQfLptIAB4ALEQgHuyU060d6edYbgc5NQ7YC+O6YQFxqJgWPyirIAAA==",
      "extra_data": "eyJiYXIiOiIyMDE4LTAzLTIwVDA1OjQ3OjQyLjkwOTA2NCswMDowMCIsImZvbyI6ImUifQ=="
    },
    {
      "leaf_input": "AAAAAAFiQfLp3oABnpTHB1x9v8GttEZD5fl/tg3i0Va3picm/9Q0c/bFiN4AAA==",
      "extra_data": "eyJiYXIiOiIyMDE4LTAzLTIwVDA1OjQ3OjQyLjkwOTA2NCswMDowMCIsImZvbyI6ImcifQ=="
    }
  ]
}
```