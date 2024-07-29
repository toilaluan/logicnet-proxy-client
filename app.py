import asyncio
import base64
import io
import os
from bson import ObjectId
import requests
import random
from datetime import date
from typing import Dict, List, Union
import time
import bittensor as bt
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Request
from threading import Thread
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi.middleware.cors import CORSMiddleware
from utils.db_client import MongoDBHandler
from pydantic import BaseModel
from utils.protocol import LogicSynapse


class ValidatorInfo(BaseModel):
    postfix: str
    uid: int
    all_uid_info: dict = {}
    sha: str = ""


def get_api_key(request: Request):
    return request.headers.get("API_KEY", get_remote_address(request))


limiter = Limiter(key_func=get_api_key)


MONGO_DB_USERNAME = os.getenv("MONGO_DB_USERNAME")
MONGO_DB_PASSWORD = os.getenv("MONGO_DB_PASSWORD")

# Define a list of allowed origins (domains)
allowed_origins = [
    "http://localhost:3000",  # Change this to the domain you want to allow
    "https://nichetensor.com",
]


class ImageGenerationService:
    def __init__(self):
        self.subtensor = bt.subtensor("finney")
        self.metagraph = self.subtensor.metagraph(23)
        mongoDBConnectUri = (
            f"mongodb://{MONGO_DB_USERNAME}:{MONGO_DB_PASSWORD}@localhost:27017"
        )
        # mongoDBConnectUri = f"mongodb://localhost:27017"
        self.dbhandler = MongoDBHandler(
            mongoDBConnectUri,
        )
        # verify db connection
        print(self.dbhandler.client.server_info())

        self.available_validators = self.dbhandler.get_available_validators()
        self.filter_validators()
        self.app = FastAPI()
        # Add CORSMiddleware to the application instance
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,  # List of allowed origins
            allow_credentials=True,
            allow_methods=["*"],  # Allows all methods
            allow_headers=["*"],  # Allows all headers
        )
        self.auth_keys = self.dbhandler.get_auth_keys()
        self.private_key = self.load_private_key()
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        model_list_entry = self.dbhandler.model_config.find_one({"name": "model_list"})
        self.model_list = model_list_entry["data"] if model_list_entry else {}
        self.message = "image-generating-subnet"
        self.signature = base64.b64encode(
            self.private_key.sign(self.message.encode("utf-8"))
        )

        self.loop = asyncio.get_event_loop()

        Thread(target=self.sync_metagraph_periodically, daemon=True).start()
        Thread(target=self.recheck_validators, daemon=True).start()

    def sync_db(self):
        new_available_validators = self.dbhandler.get_available_validators()
        for key, value in new_available_validators.items():
            if key not in self.available_validators:
                self.available_validators[key] = value
        self.auth_keys = self.dbhandler.get_auth_keys()

    def filter_validators(self) -> None:
        for hotkey in list(self.available_validators.keys()):
            self.available_validators[hotkey]["is_active"] = False
            if hotkey not in self.metagraph.hotkeys:
                print(f"Removing validator {hotkey}", flush=True)
                self.dbhandler.validators_collection.delete_one({"_id": hotkey})
                self.available_validators.pop(hotkey)

    def load_private_key(self) -> Ed25519PrivateKey:
        # Load private key from MongoDB or generate a new one
        private_key_doc = self.dbhandler.private_key.find_one()
        if private_key_doc:
            return serialization.load_pem_private_key(
                private_key_doc["key"].encode("utf-8"), password=None
            )
        else:
            print("Generating private key", flush=True)
            private_key = Ed25519PrivateKey.generate()
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
            self.dbhandler.private_key.insert_one({"key": private_key_pem})
            return private_key

    def sync_metagraph_periodically(self) -> None:
        while True:
            print("Syncing metagraph", flush=True)
            self.metagraph.sync(subtensor=self.subtensor, lite=True)
            time.sleep(60 * 10)

    def check_auth(self, key: str) -> None:
        if key not in self.dbhandler.get_auth_keys():
            raise HTTPException(status_code=401, detail="Invalid authorization key")

    async def get_credentials(
        self, request: Request, validator_info: ValidatorInfo
    ) -> Dict:
        client_ip = request.client.host
        uid = validator_info.uid
        hotkey = self.metagraph.hotkeys[uid]
        postfix = validator_info.postfix

        if not postfix:
            raise HTTPException(status_code=404, detail="Invalid postfix")

        new_validator = self.available_validators.setdefault(hotkey, {})
        new_validator.update(
            {
                "generate_endpoint": "http://" + client_ip + postfix,
                "is_active": True,
            }
        )

        print(
            f"Found validator\n- hotkey: {hotkey}, uid: {uid}, endpoint: {new_validator['generate_endpoint']}",
            flush=True,
        )
        self.dbhandler.validators_collection.update_one(
            {"_id": hotkey}, {"$set": new_validator}, upsert=True
        )

        return {
            "message": self.message,
            "signature": self.signature,
        }

    async def generate(self, request: Request, synapse: LogicSynapse) -> Dict:
        self.sync_db()
        api_key = get_api_key(request)
        self.check_auth(api_key)

        validatorItems = self.available_validators.items()
        hotkeys = [hotkey for hotkey, log in validatorItems if log["is_active"]]
        hotkeys = [hotkey for hotkey in hotkeys if hotkey in self.metagraph.hotkeys]
        stakes = [
            self.metagraph.total_stake[self.metagraph.hotkeys.index(hotkey)]
            for hotkey in hotkeys
        ]

        validators = list(zip(hotkeys, stakes))

        request_dict = {
            "payload": synapse.dict(),
            "authorization": base64.b64encode(self.public_key_bytes).decode("utf-8"),
        }
        output = None
        while len(validators) and not output:
            stakes = [stake for _, stake in validators]
            validator = random.choices(validators, weights=stakes, k=1)[0]
            hotkey, stake = validator
            validators.remove(validator)
            validator_counter = self.available_validators[hotkey].setdefault(
                "counter", {}
            )
            today_counter = validator_counter.setdefault(
                str(date.today()), {"success": 0, "failure": 0}
            )
            print(f"Selected validator: {hotkey}, stake: {stake}", flush=True)
            try:
                start_time = time.time()
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(connect=2, timeout=64)
                ) as client:
                    response = await client.post(
                        self.available_validators[hotkey]["generate_endpoint"],
                        json=request_dict,
                    )
                end_time = time.time()
                print(
                    f"Received response from validator {hotkey} in {end_time - start_time:.2f} seconds",
                    flush=True,
                )
            except Exception as e:
                print(f"Failed to send request to validator {hotkey}: {e}", flush=True)
                continue
            status_code = response.status_code
            try:
                response = response.json()
            except Exception as e:
                response = {"error": str(e)}

            if status_code == 200:
                print(f"Received response from validator {hotkey}", flush=True)
                output = response

            if output:
                today_counter["success"] += 1
            else:
                today_counter["failure"] += 1
            try:
                self.dbhandler.validators_collection.update_one(
                    {"_id": hotkey}, {"$set": self.available_validators[hotkey]}
                )
                self.auth_keys[api_key].setdefault("request_count", 0)
                self.auth_keys[api_key]["request_count"] += 1

                self.auth_keys[api_key]["credit"] -= self.model_list[
                    synapse.category
                ].get("credit_cost", 0.001)

                self.dbhandler.auth_keys_collection.update_one(
                    {"_id": api_key}, {"$set": self.auth_keys[api_key]}
                )
            except Exception as e:
                print(f"Failed to update validator - MongoDB: {e}", flush=True)
        if not output:
            if not len(self.available_validators):
                raise HTTPException(status_code=404, detail="No available validators")
            raise HTTPException(status_code=500, detail="All validators failed")
        return output

    def recheck_validators(self) -> None:
        request_dict = {
            "payload": {"recheck": True},
            "model_name": "proxy-service",
            "authorization": base64.b64encode(self.public_key_bytes).decode("utf-8"),
        }

        def check_validator(hotkey):
            with httpx.Client(timeout=httpx.Timeout(8)) as client:
                try:
                    response = client.post(
                        self.available_validators[hotkey]["generate_endpoint"],
                        json=request_dict,
                    )
                    response.raise_for_status()
                    print(f"Validator {hotkey} responded", flush=True)
                except Exception as e:
                    print(f"Validator {hotkey} failed to respond: {e}", flush=True)
                    # Set is_active to False if validator is not responding
                    self.available_validators[hotkey]["is_active"] = False

        while True:
            print("Rechecking validators", flush=True)
            threads = []
            hotkeys = list(self.available_validators.keys())
            for hotkey in hotkeys:
                thread = Thread(target=check_validator, args=(hotkey,))
                thread.start()
            for thread in threads:
                thread.join()
            print("Total validators:", len(self.available_validators), flush=True)
            # update validators to mongodb
            for hotkey in list(self.available_validators.keys()):
                self.dbhandler.validators_collection.update_one(
                    {"_id": hotkey}, {"$set": self.available_validators[hotkey]}
                )
            time.sleep(60 * 5)

    async def get_validators(self) -> List:
        return list(self.available_validators.keys())


app = ImageGenerationService()
