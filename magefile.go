// +build mage

package main

import (
	"archive/zip"
	"compress/gzip"
	"fmt"
	"github.com/magefile/mage/mg" // mg contains helpful utility functions, like Deps
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Default target to run when none is specified
// If not set, running mage will list available targets
// var Default = Build
type BuildEnv struct {
	OS       string
	ARCH     string
	FILE     string
	COMPRESS string
}

func makeGzip(filePath string) error {
	fmt.Printf("make compress %s.gz\n", filePath)
	orgfile, err := ioutil.ReadFile(filePath)

	gfile, err := os.Create(fmt.Sprintf("%s.gz", filePath))
	if err != nil {
		return errors.WithStack(err)
	}
	defer gfile.Close()
	zw, err := gzip.NewWriterLevel(gfile, gzip.BestCompression)
	if err != nil {
		return errors.WithStack(err)
	}
	defer zw.Close()

	if _, err := zw.Write(orgfile); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func makeZip(filePath string) error {
	fmt.Printf("make compress %s.zip\n", filePath)
	fileToZip, err := os.Open(filePath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer fileToZip.Close()

	info, err := fileToZip.Stat()
	if err != nil {
		return errors.WithStack(err)
	}

	newZipFile, err := os.Create(fmt.Sprintf("%s.zip", filePath))
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return errors.WithStack(err)
	}
	header.Name = filepath.Base(filePath)
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = io.Copy(writer, fileToZip)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// A build step that requires additional params, or platform specific steps for example
func Build() error {
	mg.Deps(InstallDeps)

	var buildEnvList = []BuildEnv{
		{"linux", "386", "actool-%s-i386_linux", "gz"},
		{"linux", "amd64", "actool-%s-arm64_linux", "gz"},
		{"darwin", "386", "actool-%s-i386_mac", "gz"},
		{"darwin", "amd64", "actool-%s-arm64_mac", "gz"},
		{"windows", "386", "actool-%s_win32.exe", "zip"},
		{"windows", "amd64", "actool-%s_win64.exe", "zip"},
	}

	v, err := exec.Command("git", "describe", "--tags", "--abbrev=0").Output()
	if err != nil {
		fmt.Printf("%v\n", err)
		return errors.WithStack(err)
	}
	version := string(v)
	version = strings.Trim(version, "\r\n")

	fmt.Println(fmt.Sprintf("Building %s...", version))
	for _, e := range buildEnvList {
		filePath := filepath.Join("builds", fmt.Sprintf(e.FILE, version))
		cmd := exec.Command("go", "build", "-o", filePath, "-ldflags", "-s -w", ".")
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("GOOS=%s", e.OS),
			fmt.Sprintf("GOARCH=%s", e.ARCH),
		)
		if err := cmd.Run(); err != nil {
			fmt.Printf("%v\n", err)
			return errors.WithStack(err)
		}
		if e.COMPRESS == "gz" {
			if err := makeGzip(filePath); err != nil {
				fmt.Printf("%v\n", err)
				return errors.WithStack(err)
			}
		} else if e.COMPRESS == "zip" {
			if err := makeZip(filePath); err != nil {
				fmt.Printf("%v\n", err)
				return errors.WithStack(err)
			}
		}
		os.Remove(filePath)
	}
	return nil
}

// A custom install step if you need your bin someplace other than go/bin
func Install() error {
	mg.Deps(Build)
	//fmt.Println("Installing...")
	//return os.Rename("./MyApp", "/usr/bin/MyApp")
	return nil
}

// Manage your deps, or running package managers.
func InstallDeps() error {
	fmt.Println("Installing Deps...")
	//cmd := exec.Command("go", "get", "github.com/stretchr/piglatin")
	//return cmd.Run()
	return nil
}

// Clean up after yourself
func Clean() {
	fmt.Println("Cleaning...")
	os.RemoveAll("builds")
}
