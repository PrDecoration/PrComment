package data

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/checkmarxDev/ast/test/config"
	"github.com/checkmarxDev/ast/test/utils"
	"github.com/checkmarxDev/ast/test/utils/logger"
	"github.com/checkmarxDev/ast/test/utils/wrappers"
	"github.com/pkg/errors"
)

type Source struct {
	Name string
	Url  string
}

var Sources map[string]string
var initOnce sync.Once

// TODO wil be removed once we move sources to s3
func UploadSources(filesPath string, auth ...*utils.CredentialsInfo) error {
	UploadsWrapper := wrappers.NewUploadsWrapper()

	Sources = make(map[string]string)

	return filepath.Walk(filesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		url, err := UploadsWrapper.Create(path, auth[0])
		if err != nil {
			return err
		}

		Sources[info.Name()] = *url
		return nil
	})
}

func GetSourceURLByFileName(name string, auth ...*utils.CredentialsInfo) string {
	initOnce.Do(func() {
		config.InitIntegrations()
	})
	filesPath := config.GetString(config.DataSourcePath)

	_, errStat := os.Stat(filepath.Join(filesPath, name))
	if errStat != nil {
		logger.PrintError("Error to get file info. Error: %v", errStat)
	}

	filesPath = filepath.Join(filesPath, name)
	UploadsWrapper := wrappers.NewUploadsWrapper()
	var url *string
	var err error

	if auth != nil {
		url, err = UploadsWrapper.Create(filesPath, auth[0])
	} else {
		url, err = UploadsWrapper.Create(filesPath, nil)
	}

	if err != nil {
		logger.Print("Error to create URL with filePath: %v; Error: %v", filesPath, err)
		return ""
	}

	return *url
}

func GetSourceDirectoryByFileName(name string) (string, error) {
	config.InitIntegrations()
	dataSourcePath := config.GetString(config.DataSourcePath)
	filesPath := filepath.Join(dataSourcePath, name)
	_, errStat := os.Stat(filesPath)
	if errStat != nil {
		return "", errors.Errorf("Error to get file info. Error: %v", errStat)
	}

	return filesPath, nil
}

func ImportQueries() error {
	queriesName := fmt.Sprintf("queries_%s", strconv.Itoa(rand.Int()))
	queryWrapper := wrappers.NewQueryWrapper()
	queryData := map[string]string{
		"uploadURL": GetSourceURLByFileName("queries.tar.gz"),
		"name":      queriesName,
	}
	if queryData["uploadURL"] == "" {
		return errors.Errorf("Queries upload URL is empty - check source file")
	}

	bytes, err := json.Marshal(queryData)
	if err != nil {
		return err
	}

	err = queryWrapper.ImportQueries(string(bytes))
	if err != nil {
		return err
	}

	activateData := map[string]bool{
		"activate": true,
	}
	bytes, err = json.Marshal(activateData)
	if err != nil {
		return err
	}

	return queryWrapper.ActivateQueries(queriesName, string(bytes))
}
