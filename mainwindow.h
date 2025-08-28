#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QCryptographicHash>  //SHA256计算支持
#include <QByteArray>
#include <QEvent>              // 添加：用于 eventFilter 声明
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <QProgressBar>
#include <QPushButton>
#include <QLabel>
#include <QFutureWatcher>
#include <QAtomicInteger>
#include <functional>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void bringToForeground();

protected:
    // 修复：在头文件声明 eventFilter，防止 cpp 中实现找不到声明导致链接/编译错误
    bool eventFilter(QObject *watched, QEvent *event) override;
    // 在此声明 resizeEvent（已在 cpp 中实现）
    void resizeEvent(QResizeEvent *event) override;

private slots:
    void onBackButtonClicked();
    void updateFileInfoDisplay();
    void onSelectFileClicked();
    void calculateFileHash();
    void onHashCalculationFinished();
    void onEncryptButtonClicked();
    void onEncryptionFinished();

    // 解密相关槽函数
    void onSelectDecryptFileClicked();
    void updateDecryptFileInfoDisplay();
    void onDecryptBackButtonClicked();
    void onDecryptButtonClicked();
    void onDecryptionFinished();

    // 日志相关槽函数
    void onSearchTextChanged(const QString &text);
    void onLogListCustomContextMenuRequested(const QPoint &pos);
    void onDeleteLogEntry();
    void onSaveLogEntry();
    void onCopyLogEntry();

private:
    Ui::MainWindow *ui;
    QString m_currentFilePath;
    QByteArray m_fileHash;
    // 添加加密相关成员
    QString m_encryptionKey; // 存储生成的随机密钥
    QString m_encryptedFilePath; // 存储加密后的文件路径

    // 解密相关成员
    QString m_currentDecryptFilePath; // 当前选择的解密文件路径
    QString m_originalFileExtension; // 存储原始文件扩展名
    QString m_decryptedFilePath; // 新增：用于记录最近一次解密输出路径

    // 新增：进度/取消 UI 与后台 watcher
    QWidget *m_progressOverlay = nullptr;
    QProgressBar *m_progressBar = nullptr;
    QLabel *m_progressLabel = nullptr;
    QPushButton *m_cancelButton = nullptr;
    QFutureWatcher<bool> *m_workerWatcherEncrypt = nullptr;
    QFutureWatcher<bool> *m_workerWatcherDecrypt = nullptr;
    QAtomicInteger<bool> m_cancelRequested{false};

    // 加密函数（增加进度回调）
    bool encryptFile(const QString &inputPath, const QString &outputPath, const QByteArray &key, const QByteArray &iv,
                     const std::function<void(int)> &progressCallback);
    QByteArray generateRandomData(int size);

    // 解密函数（增加进度回调）
    bool decryptFile(const QString &inputPath, const QString &outputPath, const QByteArray &key,
                     const std::function<void(int)> &progressCallback, QString *outExt = nullptr);

    // 校验解密密钥格式（十六进制、长度32）
    bool validateDecryptionKey(const QString &keyHex);

    // 日志功能
    void logOperation(const QString &operation, const QString &originalFilePath, const QString &resultFilePath,
                      qint64 originalSize, qint64 resultSize, const QString &key = QString());
    void loadLogsFromFile();
    void saveLogsToFile();
    void refreshLogList(const QString &filter = QString());
    QString getLogFilePath();
    QString formatFileSize(qint64 bytes); // <--- 添加声明

    QStringList m_logEntries; // 存储日志条目（每个元素是一条完整日志）
};
#endif
