//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"os"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgconfig"
)

const ENV_WG_CONFIG_FILE = "WG_CONFIG_FILE"

func loadConfig(device *device.Device, errs chan<- error, logger *device.Logger) {
	WG_CONFIG_FILE, _ := os.LookupEnv(ENV_WG_CONFIG_FILE)
	if len(WG_CONFIG_FILE) == 0 {
		logger.Verbosef("Config: %s - filepath not provided/empty", ENV_WG_CONFIG_FILE)
		return
	}

	cfgFile, err := os.Open(WG_CONFIG_FILE)
	if err != nil {
		logger.Errorf("Config: %s - failed on read file - %v", WG_CONFIG_FILE, err)
		errs <- nil
		return
	}
	defer cfgFile.Close()

	cfgParsed, err := wgconfig.Parse(cfgFile)
	if err != nil {
		logger.Errorf("Config: %s - failed on parse file - %v", WG_CONFIG_FILE, err)
		errs <- nil
		return
	}

	cfgRaw := new(bytes.Buffer)
	wgconfig.Write(cfgRaw, cfgParsed)

	err = device.IpcSetOperation(cfgRaw)
	if err != nil {
		logger.Errorf("Config: %s - failed on device.IpcSet - %v", WG_CONFIG_FILE, err)
		errs <- nil
		return
	}

	logger.Verbosef("Config: %s - applied", WG_CONFIG_FILE)
}
