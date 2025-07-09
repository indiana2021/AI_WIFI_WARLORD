# M5Stack LLM630 OS Installation Guide

## Summary
The M5Stack LLM630 Compute Kit ships with—and can be reflashed to run—Ubuntu 22.04 LTS (Jammy Jellyfish) using M5Stack’s Windows-based flashing tool and firmware package. You’ll download the `.axp` system image named `M5_LLM_ubuntu22.04_20250328`, install the AXDL flashing utility and driver, put the kit into bootloader mode via USB-OTG, and flash the image. Once complete, the device will boot into Ubuntu 22.04, ready for your **AI Network Guardian** stack.

*(Sources: docs.m5stack.com, cnx-software.com)*

---

## Supported Ubuntu Version
The officially supported system firmware for the LLM630 Compute Kit is **Ubuntu 22.04 LTS (Jammy Jellyfish)**, packaged as a point-release image `M5_LLM_ubuntu22.04_20250328`.

This version benefits from long-term support through April 2027 and includes the necessary kernel and device tree for the AX630C SoC.

---

## Downloading the Firmware & Tools

### Firmware Package
Visit the [LLM630 Compute Kit Firmware Upgrade page](https://docs.m5stack.com/en/core/llm630/firmware_upgrade) on the M5Stack Docs and download the `.axp` file named `M5_LLM_ubuntu22.04_20250328`.

### Flashing Utility & Driver
From the same page, download `AXDL_V1.24.13.1` (the Windows flashing tool) and `AXDL_Driver_V1.20.46` (the USB-OTG driver).

---

## Installing the Flashing Tool & Driver
1.  On a Windows 10/11 PC, run `AXDL_Driver_V1.20.46.exe` and follow the prompts to install the USB-OTG driver.
2.  Launch `AXDL_V1.24.13.1.exe` to open the flashing tool’s GUI.

---

## Flashing Ubuntu to the LLM630

### 1. Enter Download Mode
*   Press and hold the **Download** button on the Compute Kit.
*   While holding, connect the kit’s **USB-OTG Type-C port** to your Windows PC.

### 2. Load & Flash
*   In the AXDL GUI, click “Load”, select `M5_LLM_ubuntu22.04_20250328.axp`, then click “Start”.
*   Wait for the progress bar to reach 100% and confirm success.

### 3. Reboot
*   Disconnect and reconnect power (or press reset) to boot into the new Ubuntu image.

---

## Verifying Ubuntu Installation

### Access the Shell
Connect over Ethernet via SSH or use ADB/serial via USB-OTG to open a terminal.

### Check Release
Run the following command:
```bash
lsb_release -a
```
You should see **Ubuntu 22.04 LTS “Jammy Jellyfish”** as the output.
