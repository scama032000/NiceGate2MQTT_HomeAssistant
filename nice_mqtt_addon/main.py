import asyncio
import json
import logging
import os
import signal
import sys
import paho.mqtt.client as mqtt

from nice_driver import NiceGateApi

OPTIONS_PATH = "/data/options.json"

config = {
    "mqtt_broker": os.getenv("MQTT_BROKER", "core-mosquitto"),
    "mqtt_port": int(os.getenv("MQTT_PORT", 1883)),
    "mqtt_user": os.getenv("MQTT_USER", ""),
    "mqtt_pass": os.getenv("MQTT_PASS", ""),
    "nice_host": os.getenv("NICE_HOST", ""),
    "nice_mac": os.getenv("NICE_MAC", ""),
    "setup_code": os.getenv("SETUP_CODE", ""),
    "nice_pwd": os.getenv("NICE_PWD", "")
}

if os.path.exists(OPTIONS_PATH):
    try:
        with open(OPTIONS_PATH, 'r') as f:
            addon_options = json.load(f)
            for key, value in addon_options.items():
                if value is not None:
                    config[key] = value
        logging.info("Loaded configuration from Home Assistant Add-on options.")
    except Exception as e:
        logging.error(f"Error reading options.json: {e}")

MQTT_BROKER = config["mqtt_broker"]
MQTT_PORT = int(config["mqtt_port"])
MQTT_USER = config["mqtt_user"]
MQTT_PASS = config["mqtt_pass"]

if not all([MQTT_BROKER, MQTT_PORT, MQTT_USER, MQTT_PASS]):
    logging.error("MQTT configuration incomplete. Please provide: mqtt_broker, mqtt_port, mqtt_user, mqtt_pass")
    sys.exit(1)

NICE_HOST = config["nice_host"]
NICE_MAC = config["nice_mac"]
SETUP_CODE = config["setup_code"]
NICE_PWD = config["nice_pwd"]

if not all([NICE_HOST, NICE_MAC]):
    logging.error("Nice device configuration incomplete. Please provide: nice_host, nice_mac")
    sys.exit(1)

DEVICE_NAME = "Gate"
DEVICE_ID = "nice_gate_it4wifi"
TOPIC_BASE = f"nice/{DEVICE_ID}"
TOPIC_CMD = f"{TOPIC_BASE}/set"
TOPIC_STATE = f"{TOPIC_BASE}/state"
TOPIC_AVAIL = f"{TOPIC_BASE}/availability"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)

logger = logging.getLogger("main")

STATUS_MAP = {
    "closed": "closed",
    "open": "open",
    "closing": "closing",
    "opening": "opening",
    "stopped": "stopped"
}

COMMAND_MAP = {
    "STEP_BY_STEP": "MDAx",
    "STOP": "MDAy",
    "OPEN": "MDAz",
    "CLOSE": "MDA0",
    "PARTIAL_1": "MDA1",
    "PARTIAL_2": "MDA2",
    "PARTIAL_3": "MDA3",
    "APARTMENT_STEP": "MDBi",
    "STEP_HIGH_PRIORITY": "MDBj",
    "OPEN_BLOCK": "MDBk",
    "CLOSE_BLOCK": "MDBl",
    "BLOCK": "MDBm",
    "RELEASE": "MDEw",
    "COURTESY_TIMER": "MDEx",
    "COURTESY_TOGGLE": "MDEy",
    "MASTER_DOOR_STEP": "MDEz",
    "MASTER_DOOR_OPEN": "MDE0",
    "MASTER_DOOR_CLOSE": "MDE1",
    "SLAVE_DOOR_STEP": "MDE2",
    "SLAVE_DOOR_OPEN": "MDE3",
    "SLAVE_DOOR_CLOSE": "MDE4",
    "RELEASE_OPEN": "MDE5",
    "RELEASE_CLOSE": "MDFh"
}

api_instance = None
loop = None
mqtt_client = None


def on_mqtt_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        logger.info(f"Connected to MQTT Broker successfully (Code: {reason_code})")
        client.subscribe(TOPIC_CMD)

        cover_config = {
            "name": DEVICE_NAME,
            "unique_id": f"{DEVICE_ID}_cover",
            "device_class": "gate",
            "command_topic": TOPIC_CMD,
            "state_topic": TOPIC_STATE,
            "availability_topic": TOPIC_AVAIL,
            "payload_open": "OPEN",
            "payload_close": "CLOSE",
            "payload_stop": "STOP",
            "device": {
                "identifiers": [DEVICE_ID],
                "name": "Nice IT4WIFI Gate",
                "manufacturer": "Nice",
                "model": "IT4WIFI"
            }
        }
        client.publish(f"homeassistant/cover/{DEVICE_ID}/config", json.dumps(cover_config), retain=True)

        button_config = {
            "name": "Partial Opening 1",
            "unique_id": f"{DEVICE_ID}_partial_1",
            "icon": "mdi:gate-arrow-right",
            "command_topic": TOPIC_CMD,
            "payload_press": "PARTIAL_1",
            "availability_topic": TOPIC_AVAIL,
            "device": {
                "identifiers": [DEVICE_ID],
                "name": "Nice IT4WIFI Gate",
                "manufacturer": "Nice",
                "model": "IT4WIFI"
            }
        }
        client.publish(f"homeassistant/button/{DEVICE_ID}_partial_1/config", json.dumps(button_config), retain=True)

        client.publish(TOPIC_AVAIL, "online", retain=True)
    else:
        logger.error(f"Failed to connect to MQTT Broker. Reason code: {reason_code}")


def on_mqtt_message(client, userdata, msg):
    payload = msg.payload.decode().upper()
    logger.info(f"Received MQTT command: {payload}")

    if api_instance and loop:
        command_code = COMMAND_MAP.get(payload)
        if command_code:
            coro = api_instance.t4(command_code)
            asyncio.run_coroutine_threadsafe(coro, loop)
        else:
            logger.warning(f"Unknown command: {payload}")


def nice_status_callback(status):
    """Called when gate status changes"""
    logger.info(f"Nice Callback Status Raw: '{status}'")

    status_clean = str(status).strip() if status else "unknown"
    ha_status = STATUS_MAP.get(status_clean, "unknown")

    if ha_status == "unknown":
        logger.warning(f"Status '{status_clean}' not found in STATUS_MAP. Available: {list(STATUS_MAP.keys())}")
        ha_status = status_clean.lower()

    mqtt_client.publish(TOPIC_STATE, ha_status, retain=True)


async def main():
    global api_instance, loop, mqtt_client
    loop = asyncio.get_running_loop()

    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

    if MQTT_USER:
        mqtt_client.username_pw_set(MQTT_USER, MQTT_PASS)

    mqtt_client.on_connect = on_mqtt_connect
    mqtt_client.on_message = on_mqtt_message

    try:
        mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
        mqtt_client.loop_start()
    except Exception as e:
        logger.error(f"Failed to connect to MQTT: {e}")
        return

    logger.info("Initializing Nice API...")
    api_instance = NiceGateApi(
        NICE_HOST,
        NICE_MAC,
        NICE_PWD,
        on_status_callback=nice_status_callback
    )

    try:
        if not NICE_PWD:
            logger.info("No password provided, attempting to pair using setup code...")
            paired_pwd = await api_instance.pair(SETUP_CODE)
            if paired_pwd:
                logger.info("Pairing successful, please update your configuration with the new password.")
                logger.info(f"New password: {paired_pwd}")
            else:
                logger.error("Pairing failed, cannot proceed without a password.")
                return
            logger.info("Paired successfully, now the addon will stop. Please authorize the new user in the NiceWelcome app and restart the addon.")
            return
        await api_instance.start()

        while True:
            await asyncio.sleep(3600)

    except asyncio.CancelledError:
        logger.info("Stopping...")
    finally:
        await api_instance.close()
        mqtt_client.publish(TOPIC_AVAIL, "offline")
        mqtt_client.loop_stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass