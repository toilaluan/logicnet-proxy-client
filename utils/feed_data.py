VALIDATORS_FEED = [
    {
        "_id": "[validator_id]",
        "generate_endpoint": "http://[validator_addr]/validator_proxy",
        "is_active": True,
        "counter": {"2024-06-19": {"success": 0, "failure": 0}},
    }
]
AUTH_KEYS_FEED = [
    {"_id": "[auth_key]", "request_count": 0, "credit": 10, "email": "", "password": ""}
]
