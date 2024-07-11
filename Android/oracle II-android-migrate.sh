
# 检查输入参数的个数
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <backup/recover> <package_name>"
    exit 1
fi

# 获取输入的命令（backup/recover）和包名
COMMAND=$1
PACKAGE=$2

# 定义备份和恢复的路径
BACKUP_PATH=/storage/emulated/0/Android/data/$PACKAGE
DATA_PATH=/data/data/$PACKAGE
OBB_PATH=/storage/emulated/0/Android/obb/$PACKAGE
MEDIA_PATH=/storage/emulated/0/Android/media/$PACKAGE
DE_PATH=/data/user_de/0/$PACKAGE
ARCHIVE_PATH=/sdcard/$PACKAGE.tar.gz

# 根据输入的命令执行备份或恢复操作
case $COMMAND in
    backup)
        # 备份操作
        echo "Backing up $PACKAGE..."

        # 使用tar命令创建压缩包
        tar -czf $ARCHIVE_PATH -C $BACKUP_PATH . -C $DATA_PATH .

        echo "Backup completed: $ARCHIVE_PATH"
        ;;

    recover)
        # 恢复操作
        echo "Recovering $PACKAGE..."

        # 先解压到一个临时目录
        TEMP_DIR=/sdcard/temp_$PACKAGE
        mkdir -p $TEMP_DIR
        tar -xzf $ARCHIVE_PATH -C $TEMP_DIR

        # 将数据复制回原始路径
        cp -Rf $TEMP_DIR/* $BACKUP_PATH/
        cp -Rf $TEMP_DIR/* $DATA_PATH/

        # 清理临时文件

        echo "Recovery completed."
        ;;

    *)
        # 如果输入的命令既不是backup也不是recover
        echo "Invalid command: $COMMAND"
        echo "Usage: $0 <backup/recover> <package_name>"
        exit 1
        ;;
esac

