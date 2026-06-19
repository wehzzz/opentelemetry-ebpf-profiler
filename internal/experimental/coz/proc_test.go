// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package coz

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProcTIDSourceCurrentProcess(t *testing.T) {
	tids, err := procTIDSource{}.TIDs(os.Getpid(), 1024)
	require.NoError(t, err)
	require.NotEmpty(t, tids)
}

func TestProcTIDSourceMaxThreads(t *testing.T) {
	_, err := procTIDSource{}.TIDs(os.Getpid(), 0)
	require.ErrorContains(t, err, "max threads")
}
