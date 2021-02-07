#https://unix.stackexchange.com/questions/310752/how-do-i-configure-wpa-supplicant-conf-for-wps-push-button



#Edit your /etc/wpa_supplicant.conf configuration file as follow:
#
#    At least you need to add the following line :
#
#        ctrl_interface=/var/run/wpa_supplicant
#        ctrl_interface_group=0
#        update_config=1
#        CONFIG_DRIVER_NL80211=y
#        You can enable some others support:
#
#             ctrl_interface=/var/run/wpa_supplicant
#             ctrl_interface_group=0
#             update_config=1
#             CONFIG_DRIVER_NL80211=y
#             CONFIG_WPS=y
#             CONFIG_WPS2=y
#             CONFIG_WPS_ER=y
#             CONFIG_WPS_NFC=y
#             uuid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx 
#         Get the uuid through status command from wpa_cli
#
#         To connect
#
#             run wpa_cli
#             From the Interactive mode, run wps_pbc and push the wps button.
#             Once connected run dhclient wlan0 (change wlan0 with your interface wifi)



#See the documentation at w1.fi/cgit/hostap/plain/wpa_supplicant/README-WPS.
#
#The documentation you were looking at shows all the possible options in wpa_supplicant.conf, which includes options for static configuration.
#
#You also need to write a script so that when the WPS button on your device is pressed then you execute wpa_cli wps_pbc to alert wpa_supplicant. It's also a good idea to capture a multisecond key-press and use that to reset wpa_supplicant's configuration (allowing the user to move your device).
