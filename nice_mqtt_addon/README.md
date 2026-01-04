# Nice-IT4WIFI to MQTT HomeAssistant AddOn

## Description

This repository contains an AddOn for HomeAssistant that allows integration with Nice IT4WIFI devices via MQTT. This is not an official integration.

## AddOn Installation

You can clone this repository or add it to the online repository in the addon store

IMPORTANT: this addon works only with the gate set up in the "MyNice Welcome" app (not the new "My Nice"). this because only in the old app you can control the new user connecting to your accessory. For android user you can find the apk online given that it was removed from Google Play. I don't know if an equivalent app is available on iPhone (without using HK).

## AddOn Configuration

You need to have a working MQTT broker (you can use HA addon)
Before launching the addon complete the configuration

```
# Complete with your broker address (if you use homeassistant addon you can leave the default value)
mqtt_broker: "core-mosquitto"
# Your MQTT broker port
mqtt_port: 1883
# Your MQTT user (This addon works only if you have user and password but it can be changed in future releases if necessary)
mqtt_user: ""
# Your MQTT password
mqtt_pass: ""
# The IP address of your Gate (you can find it in the router settings or in the accessory info in the Nice App)
nice_host: ""
# The MAC of the gate (it is written in the setup label of the IT4WIFI)
nice_mac: ""
# Setup Code of the gate (it is written in the setup label of the IT4WIFI)
setup_code: ""
# For the first binding you must leave password empty then complete with the password shown in the logs
nice_pwd: ""
```
After completing the configuration you can launch the addon. If everything goes well, the addon will stop and will give you a long password in the logs. You must copy that password and insert it in the configuration. Then you need to open your "My Nice Welcome" app and authorize the new user ("homeasistant").
After completing this procedure, you can launch the addon and you will see in your MQTT device the gate (you must set up MQTT integration)

# How to authorize user in My Nice Welcome app

Open the app andopen settings (bottom right button). Then select User Management, select your accessory. You should see a request from "homeassistant"

# Possible Bugs

Due to sockets managing of the IT4WIFI could happen that, while your server closes sockets when disconnected, the device is flooded with zombie connection making it unavailble on the wifi. It should be rare (if last bug fixing did not already solve that) but if it happens you can connect your mobile phone via mobile data and restart the device via Nice app or you can restart your router.

# Info

* Currently an integration cannot be developed due to old ssl requirements of the device (which cannot be used in recent python versions like the one for home assistant integration)

* I'm a simple customer and a programmer and I did this addon to use my own gate with Home Assistant, so I tested only commands working with my gate. All the commands available in the app should have been mapped to MQTT. Given that this is not an official addon, I do not promise I will be always available to fix bugs (unless they compromise also my gate) but I'll try to do my best ;)
