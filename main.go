// ftpserver allows to create your own FTP(S) server
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"net/http"

	"time"

	"github.com/Sirupsen/logrus"
	"github.com/chosenken/ftpserver/db"
	"github.com/chosenken/ftpserver/driver"
	"github.com/chosenken/ftpserver/server"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

var (
	ftpServer *server.FtpServer
	svc       *http.Server
	logger    *logrus.Logger
)

func main() {
	logger = logrus.New()
	logger.Level = logrus.DebugLevel

	viper.AutomaticEnv()
	viper.SetDefault("db_path", "/mnt/users.db")
	viper.SetDefault("http_port", "8080")

	dbClient, err := db.NewClient(viper.GetString("db_path"), logger)
	if err != nil {
		logger.Error(err)
		os.Exit(1)
	}

	// Loading the driver
	drivr := driver.NewDriver(logger, dbClient)

	// Instantiating the server by passing our driver implementation
	ftpServer = server.NewFtpServer(drivr, logger)

	logger.Debug("Before http server")
	httpServer(dbClient)

	// Preparing the SIGTERM handling
	go signalHandler()
	logger.Debug("Before ftp server")
	if err := ftpServer.ListenAndServe(); err != nil {
		logger.WithField("error", err).Error("Error listening")
	}
}

func signalHandler() {
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGTERM)
	for {
		switch <-ch {
		case syscall.SIGTERM:
			ftpServer.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := svc.Shutdown(ctx); err != nil {
				logger.Fatal("Server Shutdown:", err)
			}
			break
		}
	}
}

func httpServer(dbc *db.Client) {
	router := gin.Default()
	router.GET("/user", func(c *gin.Context) {
		userName := c.Query("username")
		if userName == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "parameter username is required"})
			return
		}
		user, err := dbc.GetUser(userName)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
	})

	router.DELETE("/user", func(c *gin.Context) {
		userName := c.Query("username")
		if userName == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "parameter password is required"})
			return
		}
		err := dbc.DeleteUser(userName)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		c.Status(http.StatusOK)
	})

	router.POST("/user", func(c *gin.Context) {
		userName := c.Query("username")
		if userName == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "parameter username is required"})
			return
		}
		password := c.Query("password")
		if password == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "parameter password is required"})
			return
		}
		dir := c.Query("dir")
		if dir == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "parameter dir is required"})
			return
		}
		err := dbc.PutUser(&db.User{
			Dir:      dir,
			Password: password,
			Username: userName,
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		c.Status(http.StatusOK)
	})

	svc = &http.Server{
		Addr:    ":" + viper.GetString("http_port"),
		Handler: router,
	}
	go func() {
		if err := svc.ListenAndServe(); err != nil {
			logger.Fatalf("listen: %s\n", err)
		}
	}()
}
