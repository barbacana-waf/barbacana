# With on_oversize: inspect_prefix the body goes through...
POST {{host}}/raw/data
Content-Type: application/json
file,fixtures/big.json;
HTTP 200

# ...an attack inside the window is still blocked...
POST {{host}}/raw/data
Content-Type: application/json
file,fixtures/big-attack-first.json;
HTTP 403

# ...and one past the window is not seen. That is the price of the option.
POST {{host}}/raw/data
Content-Type: application/json
file,fixtures/big-attack-last.json;
HTTP 200
