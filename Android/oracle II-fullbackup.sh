# 检查输入参数的个数
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <backup/recover> <package_name>"
    exit 1
fi

# 获取输入的命令（backup/recover）和包名
COMMAND=$1
PACKAGE=$2


case $COMMAND in
    backup)
        echo "Backup $PACKAGE..."
        adb push migrate.sh /sdcard/
        adb shell "su -c 'cp /sdcard/migrate.sh /data/local/tmp/migrate.sh && chmod +x /data/local/tmp/migrate.sh;/data/local/tmp/migrate.sh backup $PACKAGE'"
        adb pull /sdcard/$PACKAGE.tar.gz
        echo "Backup completed: $PACKAGE.tar.gz"
        ;;
    
    recover)
        echo "Recover $PACKAGE..."
        adb push migrate.sh /sdcard/
        adb push $PACKAGE.tar.gz /sdcard/
        adb shell "su -c 'cp /sdcard/migrate.sh /data/local/tmp/migrate.sh && chmod +x /data/local/tmp/migrate.sh; /data/local/tmp/migrate.sh recover $PACKAGE'"
        echo "Recover completed."
        ;;

    *)
        echo "Invalid command: $COMMAND"
        echo "Usage: $0 <backup/recover> <package_name>"
        exit 1
        ;;
esac

    
