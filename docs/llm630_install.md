Summary
The M5Stack LLM630 Compute Kit ships with—and can be reflashed to run—Ubuntu 22.04 LTS (Jammy Jellyfish) using M5Stack’s Windows-based flashing tool and firmware package. You’ll download the .axp system image named M5_LLM_ubuntu22.04_20250328, install the AXDL flashing utility and driver, put the kit into bootloader mode via USB-OTG, and flash the image. Once complete, the device will boot into Ubuntu 22.04, ready for your Wi-Fi Warlord stack. 
docs.m5stack.com
cnx-software.com

Supported Ubuntu Version
The officially supported system firmware for the LLM630 Compute Kit is Ubuntu 22.04 LTS (Jammy Jellyfish), packaged as a point-release image M5_LLM_ubuntu22.04_20250328. 
docs.m5stack.com

This version benefits from long-term support through April 2027 and includes the necessary kernel and device tree for the AX630C SoC. 
cnx-software.com

Downloading the Firmware & Tools
Firmware Package

Visit the LLM630 Compute Kit Firmware Upgrade page on the M5Stack Docs and download the .axp file named M5_LLM_ubuntu22.04_20250328. 
docs.m5stack.com

Flashing Utility & Driver

From the same page, download AXDL_V1.24.13.1 (the Windows flashing tool) and AXDL_Driver_V1.20.46 (the USB-OTG driver). 
docs.m5stack.com

Installing the Flashing Tool & Driver
On a Windows 10/11 PC, run AXDL_Driver_V1.20.46.exe and follow the prompts to install the USB-OTG driver. 
docs.m5stack.com

Launch AXDL_V1.24.13.1.exe to open the flashing tool’s GUI. 
docs.m5stack.com

Flashing Ubuntu to the LLM630
Enter Download Mode

Press and hold the Download button on the Compute Kit.

While holding, connect the kit’s USB-OTG Type-C port to your Windows PC. 
docs.m5stack.com

Load & Flash

In the AXDL GUI, click “Load”, select M5_LLM_ubuntu22.04_20250328.axp, then click “Start”. 
docs.m5stack.com

Wait for the progress bar to reach 100 % and confirm success. 
docs.m5stack.com

Reboot

Disconnect and reconnect power (or press reset) to boot into the new Ubuntu image. 
docs.m5stack.com

Verifying Ubuntu Installation
Access the Shell

Connect over Ethernet via SSH or use ADB/serial via USB-OTG to open a terminal. 
docs.m5stack.com

Check Release

Run:


lsb_release -a
You should see Ubuntu 22.04 LTS “Jammy Jellyfish”. 
cnx-software.com

