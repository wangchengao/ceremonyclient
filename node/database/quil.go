package database

import (
	"log"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type FrameDataStaticDB struct {
	ID          uint `gorm:"primaryKey"`
	PeerId      string
	Ring        uint64
	FrameNumber uint64 `gorm:"index"`
	AccountName string
	OutputCnt   int
	CreatedAt   time.Time
}

// set your database dsn here
var dsn = ""
var DB *gorm.DB

func InitDB() {
	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Database connected successfully")

	err = DB.AutoMigrate(&FrameDataStaticDB{})
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
	log.Println("Database migrated successfully")
}

func WriteFrameInfoToMySQL(frameInfoList []*FrameDataStaticDB) error {
	// 插入数据
	for _, frameInfo := range frameInfoList {
		if err := DB.Create(frameInfo).Error; err != nil {
			return err
		}
	}
	return nil
}

func GetFrameDataBetweenFrames(startFrame, endFrame uint64) ([]*FrameDataStaticDB, error) {

	var frameDataList []*FrameDataStaticDB
	err := DB.Where("frame_number BETWEEN ? AND ?", startFrame, endFrame).Find(&frameDataList).Error
	if err != nil {
		return nil, err
	}

	return frameDataList, nil
}
