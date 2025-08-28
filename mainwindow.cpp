#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QDir>
#include <QFile>
#include <QtConcurrent>
#include <QCryptographicHash>
#include <QResizeEvent>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <QDesktopServices>
#include <QUrl>
#include <QClipboard>
#include <QFutureWatcher>
#include <openssl/err.h>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDateTime>
#include <QProcess>
#include <QTextCursor>
#include <QTextBlock>
#include <QTextDocumentFragment>
#include <QScrollBar>
#include <QStringConverter>
#include <QMenu>
#include <QAction>
#include <QStandardPaths>   // for getLogFilePath
#include <algorithm>        // 添加：std::sort 等
#include <future>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QThreadPool>
#include <QtConcurrent>

// 在使用之前声明 helper（防止“找不到标识符”错误）
static void setWidgetInteractiveRecursive(QWidget *root, bool enable, QWidget *exclude = nullptr);

#ifdef Q_OS_WIN
#  include <windows.h>
#  include <winuser.h>
#endif

static void handleOpenSSLErrors()
{
    ERR_print_errors_fp(stderr);
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_currentFilePath("")
    , m_currentDecryptFilePath("")
    , m_originalFileExtension("")
{
    ui->setupUi(this);

    // 安装 eventFilter 并调整 sizePolicy，确保在窗口缩放或布局变化时标签能正确重绘和 elideText 计算宽度
    if (ui->labelFileNameValue) {
        ui->labelFileNameValue->installEventFilter(this);
        ui->labelFileNameValue->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    }
    if (ui->labelFilePathValue) {
        ui->labelFilePathValue->installEventFilter(this);
        ui->labelFilePathValue->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    }
    if (ui->labelDecryptFileNameValue) {
        ui->labelDecryptFileNameValue->installEventFilter(this);
        ui->labelDecryptFileNameValue->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    }
    if (ui->labelDecryptFilePathValue) {
        ui->labelDecryptFilePathValue->installEventFilter(this);
        ui->labelDecryptFilePathValue->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    }

    // 创建覆盖式进度面板（初始隐藏）
    m_progressOverlay = new QWidget(this);
    m_progressOverlay->setObjectName("progressOverlay");
    m_progressOverlay->setVisible(false);
    m_progressOverlay->setAttribute(Qt::WA_StyledBackground, true);
    m_progressOverlay->setStyleSheet("QWidget#progressOverlay { background: rgba(0,0,0,80%); }");
    m_progressOverlay->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    QWidget *centerWidget = new QWidget(m_progressOverlay);
    centerWidget->setFixedWidth(400);
    QVBoxLayout *centerLayout = new QVBoxLayout(centerWidget);
    centerLayout->setContentsMargins(12,12,12,12);
    centerLayout->setSpacing(8);

    m_progressBar = new QProgressBar(centerWidget);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setTextVisible(false);
    m_progressBar->setStyleSheet("QProgressBar::chunk { background-color: #4caf50; }"); // 绿色填充
    m_progressBar->setFixedHeight(20);

    m_progressLabel = new QLabel("0%", centerWidget);
    m_progressLabel->setAlignment(Qt::AlignCenter);
    m_progressLabel->setStyleSheet("color: white; font-weight: bold;");

    m_cancelButton = new QPushButton(tr("取消"), centerWidget);
    m_cancelButton->setFixedWidth(100);

    centerLayout->addWidget(m_progressBar);
    centerLayout->addWidget(m_progressLabel);
    centerLayout->addWidget(m_cancelButton, 0, Qt::AlignHCenter);

    QHBoxLayout *overlayLayout = new QHBoxLayout(m_progressOverlay);
    overlayLayout->addStretch();
    overlayLayout->addWidget(centerWidget);
    overlayLayout->addStretch();
    overlayLayout->setContentsMargins(0, 0, 0, 0);

    // wire cancel
    connect(m_cancelButton, &QPushButton::clicked, this, [this](){
        m_cancelRequested.storeRelaxed(true);
        m_cancelButton->setEnabled(false);
    });

    // watcher
    m_workerWatcherEncrypt = new QFutureWatcher<bool>(this);
    m_workerWatcherDecrypt = new QFutureWatcher<bool>(this);
    connect(m_workerWatcherEncrypt, &QFutureWatcher<bool>::finished, this, &MainWindow::onEncryptionFinished);
    connect(m_workerWatcherDecrypt, &QFutureWatcher<bool>::finished, this, &MainWindow::onDecryptionFinished);

    // 确保 overlay 初始大小正确（resizeEvent 会在之后保持同步）
    m_progressOverlay->setGeometry(this->rect());

    // 其它初始化与连接（保持原有连接）
    connect(ui->stackedWidgetEncrypt, &QStackedWidget::currentChanged, this, [this](int idx){
        Q_UNUSED(idx);
        updateFileInfoDisplay();
    });
    connect(ui->stackedWidgetDecrypt, &QStackedWidget::currentChanged, this, [this](int idx){
        Q_UNUSED(idx);
        updateDecryptFileInfoDisplay();
    });

    // 加密选项卡连接
    connect(ui->btnSelectFile, &QPushButton::clicked, this, &MainWindow::onSelectFileClicked);
    connect(ui->btnBack, &QPushButton::clicked, this, &MainWindow::onBackButtonClicked);
    connect(ui->btnEncrypt, &QPushButton::clicked, this, &MainWindow::onEncryptButtonClicked);

    // 解密选项卡连接
    connect(ui->btnSelectDecryptFile, &QPushButton::clicked, this, &MainWindow::onSelectDecryptFileClicked);
    connect(ui->btnDecryptBack, &QPushButton::clicked, this, &MainWindow::onDecryptBackButtonClicked);
    connect(ui->btnDecrypt, &QPushButton::clicked, this, &MainWindow::onDecryptButtonClicked);

    // 日志选项卡：使用单一搜索框和 QListWidget
    if (ui->lineEditSearch) {
        connect(ui->lineEditSearch, &QLineEdit::textChanged, this, &MainWindow::onSearchTextChanged);
    }
    if (ui->listWidgetLogs) {
        ui->listWidgetLogs->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(ui->listWidgetLogs, &QListWidget::customContextMenuRequested,
                this, &MainWindow::onLogListCustomContextMenuRequested);

        // 修复：确保长路径完整显示
        ui->listWidgetLogs->setWordWrap(true);                       // 启用自动换行
        ui->listWidgetLogs->setTextElideMode(Qt::ElideNone);         // 取消省略号截断
        ui->listWidgetLogs->setUniformItemSizes(false);              // 允许不同高度的条目
        ui->listWidgetLogs->setSelectionMode(QAbstractItemView::ExtendedSelection);
    }

    // 加载已有日志
    loadLogsFromFile();
    refreshLogList();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::bringToForeground()
{
#ifdef Q_OS_WIN
    // Windows平台下将窗口前置
    ::SetWindowPos((HWND)this->winId(), HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    ::SetWindowPos((HWND)this->winId(), HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
#endif
    this->show();
    this->activateWindow();
    this->raise();
}

bool MainWindow::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::Resize) {
        if (watched == ui->labelFileNameValue || watched == ui->labelFilePathValue) {
            updateFileInfoDisplay();
        }
        else if (watched == ui->labelDecryptFileNameValue || watched == ui->labelDecryptFilePathValue) {
            updateDecryptFileInfoDisplay();
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void MainWindow::onBackButtonClicked()
{
    // 重新选择要加密的文件（弹出资源管理器）
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("选择要加密的文件"),
        QString(),
        tr("All Files (*)")
    );

    if (filePath.isEmpty()) {
        // 用户取消时返回选择页面
        ui->stackedWidgetEncrypt->setCurrentIndex(0);
        return;
    }

    // 限制文件大小不超过1GB
    const qint64 MAX_SIZE = 1024LL * 1024LL * 1024LL;
    QFileInfo fi(filePath);
    if (fi.exists() && fi.size() > MAX_SIZE) {
        QMessageBox::warning(this, tr("文件过大"),
                             tr("文件过大，可以使用压缩软件分卷后选择其中一部分"));
        ui->stackedWidgetEncrypt->setCurrentIndex(0);
        return;
    }

    m_currentFilePath = filePath;
    updateFileInfoDisplay();
}

void MainWindow::updateFileInfoDisplay()
{
    if (m_currentFilePath.isEmpty()) {
        ui->stackedWidgetEncrypt->setCurrentIndex(0);
        return;
    }

    QFileInfo fileInfo(m_currentFilePath);
    QString fileName = fileInfo.fileName();
    QFontMetrics fm(ui->labelFileNameValue->font());

    // 文件名显示
    // 防止宽度为负或为0导致 elidedText 返回空，从而看起来“隐藏”
    int fileNameWidth = qMax(50, ui->labelFileNameValue->width() - 10);
    QString elidedFileName = fm.elidedText(fileName, Qt::ElideMiddle, fileNameWidth);
    if (elidedFileName.isEmpty()) elidedFileName = fileName; // 回退显示原始名
    ui->labelFileNameValue->setText(elidedFileName);
    ui->labelFileNameValue->setToolTip(fileName);
    ui->labelFileNameValue->setVisible(true);

    // 文件路径显示
    QString fullPath = QDir::toNativeSeparators(fileInfo.absoluteFilePath());
    int pathWidth = qMax(50, ui->labelFilePathValue->width() - 10);
    QString elidedPath = fm.elidedText(fullPath, Qt::ElideMiddle, pathWidth);
    if (elidedPath.isEmpty()) elidedPath = fullPath;
    ui->labelFilePathValue->setText(elidedPath);
    ui->labelFilePathValue->setToolTip(fullPath);
    ui->labelFilePathValue->setVisible(true);

    // 文件大小显示
    qint64 fileSize = fileInfo.size();
    QString sizeText;
    if (fileSize < 1024) {
        sizeText = QString("%1 字节").arg(fileSize);
    } else if (fileSize < 1024 * 1024) {
        sizeText = QString("%1 KB").arg(QString::number(fileSize / 1024.0, 'f', 2));
    } else if (fileSize < 1024 * 1024 * 1024) {
        sizeText = QString("%1 MB").arg(QString::number(fileSize / (1024.0 * 1024.0), 'f', 2));
    } else {
        sizeText = QString("%1 GB").arg(QString::number(fileSize / (1024.0 * 1024.0 * 1024.0), 'f', 2));
    }
    ui->labelFileSizeValue->setText(sizeText);

    // 切换到文件信息页面
    ui->stackedWidgetEncrypt->setCurrentIndex(1);

    // 开始计算文件哈希
    calculateFileHash();
}

void MainWindow::onSelectFileClicked()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("选择要加密的文件"),
        QString(),
        tr("All Files (*)")
    );

    if (filePath.isEmpty()) {
        return;
    }

    // 限制文件大小不超过1GB
    const qint64 MAX_SIZE = 1024LL * 1024LL * 1024LL;
    QFileInfo fi(filePath);
    if (fi.exists() && fi.size() > MAX_SIZE) {
        QMessageBox::warning(this, tr("文件过大"),
                             tr("文件过大，可以使用压缩软件分卷后选择其中一部分"));
        return;
    }

    m_currentFilePath = filePath;
    updateFileInfoDisplay();
}

void MainWindow::calculateFileHash()
{
    ui->labelFileHashValue->setText(tr("计算中..."));

    // 使用QtConcurrent在后台线程计算哈希
    QFutureWatcher<QByteArray> *watcher = new QFutureWatcher<QByteArray>(this);
    connect(watcher, &QFutureWatcher<QByteArray>::finished, this, &MainWindow::onHashCalculationFinished);
    connect(watcher, &QFutureWatcher<QByteArray>::finished, watcher, &QFutureWatcher<QByteArray>::deleteLater);

    QFuture<QByteArray> future = QtConcurrent::run([this]() {
        QFile file(m_currentFilePath);
        if (!file.open(QIODevice::ReadOnly)) {
            return QByteArray();
        }

        QCryptographicHash hash(QCryptographicHash::Sha256);
        if (hash.addData(&file)) {
            return hash.result();
        }

        return QByteArray();
    });

    watcher->setFuture(future);
}

void MainWindow::onHashCalculationFinished()
{
    QFutureWatcher<QByteArray> *watcher = static_cast<QFutureWatcher<QByteArray>*>(sender());
    if (!watcher) {
        return;
    }

    QByteArray result = watcher->result();
    if (result.isEmpty()) {
        ui->labelFileHashValue->setText(tr("计算失败"));
        return;
    }

    m_fileHash = result;
    ui->labelFileHashValue->setText(m_fileHash.toHex());
}

// 当用户点击开始加密
void MainWindow::onEncryptButtonClicked()
{
    if (m_currentFilePath.isEmpty()) {
        QMessageBox::warning(this, tr("警告"), tr("请先选择要加密的文件"));
        return;
    }

    const qint64 MAX_SIZE = 1024LL * 1024LL * 1024LL;
    QFileInfo fi(m_currentFilePath);
    if (!fi.exists() || fi.size() > MAX_SIZE) {
        QMessageBox::warning(this, tr("文件过大"),
                             tr("文件过大，可以使用压缩软件分卷后选择其中一部分"));
        return;
    }

    // 生成随机密钥和IV
    QByteArray key = generateRandomData(16); // 128位密钥
    QByteArray iv = generateRandomData(12);  // 96位IV

    if (key.isEmpty() || iv.isEmpty()) {
        QMessageBox::critical(this, tr("错误"), tr("生成随机密钥失败"));
        return;
    }

    QFileInfo fileInfo(m_currentFilePath);
    QString defaultName = fileInfo.completeBaseName() + ".sefs";
    QString savePath = QFileDialog::getSaveFileName(
        this,
        tr("保存加密文件"),
        QDir::homePath() + "/" + defaultName,
        tr("SEFS Files (*.sefs)")
    );

    if (savePath.isEmpty()) {
        return;
    }

    if (!savePath.endsWith(".sefs", Qt::CaseInsensitive)) savePath += ".sefs";

    // 锁定页面交互并显示进度 overlay
    m_cancelRequested.storeRelaxed(false);
    m_progressBar->setValue(0);
    m_progressLabel->setText("0%");
    m_cancelButton->setEnabled(true);
    m_progressOverlay->setGeometry(this->rect());
    m_progressOverlay->setVisible(true);

    // 禁用当前加密页面内其他控件（exclude overlay）
    QWidget *pageWidget = ui->stackedWidgetEncrypt->currentWidget();
    setWidgetInteractiveRecursive(pageWidget, false, m_progressOverlay);

    // 开始后台任务，传入进度回调（线程安全：使用 Qt::QueuedConnection via lambda captures）
    auto progressCb = [this](int percent){
        // 更新 UI 在主线程
        QMetaObject::invokeMethod(this, [this, percent](){
            m_progressBar->setValue(percent);
            m_progressLabel->setText(QString::number(percent) + "%");
        }, Qt::QueuedConnection);
    };

    // 使用 QtConcurrent 在后台执行 encryptFile
    auto future = QtConcurrent::run([this, savePath, key, iv, progressCb]() -> bool {
        bool ok = this->encryptFile(this->m_currentFilePath, savePath, key, iv, progressCb);
        // store values on success
        if (ok) {
            this->m_encryptionKey = key.toHex();
            this->m_encryptedFilePath = savePath;
        }
        return ok;
    });

    m_workerWatcherEncrypt->setFuture(future);
}

// 完成槽（由 watcher 触发）
void MainWindow::onEncryptionFinished()
{
    bool success = m_workerWatcherEncrypt->result();

    // 隐藏 overlay 并恢复页面可交互（保持在当前页，不跳回）
    m_progressOverlay->setVisible(false);
    QWidget *pageWidget = ui->stackedWidgetEncrypt->currentWidget();
    setWidgetInteractiveRecursive(pageWidget, true, m_progressOverlay);

    if (success) {
        // 记录日志
        QFileInfo originalFileInfo(m_currentFilePath);
        QFileInfo encryptedFileInfo(m_encryptedFilePath);
        logOperation("加密", m_currentFilePath, m_encryptedFilePath,
                     originalFileInfo.size(), encryptedFileInfo.size(), m_encryptionKey);

        QMessageBox msgBox(this);
        msgBox.setWindowTitle(tr("加密成功"));
        msgBox.setText(tr("文件加密成功！\n\n密钥: %1\n\n请妥善保管此密钥，解密时需要用到。").arg(m_encryptionKey));
        QPushButton *copyButton = msgBox.addButton(tr("复制密钥"), QMessageBox::ActionRole);
        msgBox.addButton(QMessageBox::Ok);
        msgBox.exec();
        if (msgBox.clickedButton() == copyButton) {
            QApplication::clipboard()->setText(m_encryptionKey);
            QMessageBox::information(this, tr("复制成功"), tr("密钥已复制到剪贴板"));
        }

        // 不自动跳回上一页（用户可继续）
        // 清空选择但保留当前页显示（如需清空可选择性清理）
        m_currentFilePath.clear();
        updateFileInfoDisplay();
    } else {
        if (m_cancelRequested.loadRelaxed()) {
            QMessageBox::information(this, tr("已取消"), tr("加密已取消"));
        } else {
            QMessageBox::critical(this, tr("错误"), tr("文件加密失败"));
        }
    }
}

// 对解密也做同样处理（开始任务、显示 overlay、watcher 触发完成）
// onDecryptButtonClicked
void MainWindow::onDecryptButtonClicked()
{
    if (m_currentDecryptFilePath.isEmpty()) {
        QMessageBox::warning(this, tr("警告"), tr("请先选择要解密的文件"));
        return;
    }

    // 解密密钥从 UI 读取（示例）
    QString keyHex = ui->lineEditDecryptKey->text().trimmed();
    if (!validateDecryptionKey(keyHex)) {
        QMessageBox::warning(this, tr("密钥错误"), tr("请提供有效的解密密钥（十六进制）"));
        return;
    }
    QByteArray key = QByteArray::fromHex(keyHex.toUtf8());

    QString defaultOut = QDir::homePath() + "/" + QFileInfo(m_currentDecryptFilePath).completeBaseName();
    QString savePath = QFileDialog::getSaveFileName(this, tr("保存解密文件"), defaultOut, tr("All Files (*)"));
    if (savePath.isEmpty()) return;

    // 显示 overlay 并禁用页面
    m_cancelRequested.storeRelaxed(false);
    m_progressBar->setValue(0);
    m_progressLabel->setText("0%");
    m_cancelButton->setEnabled(true);
    m_progressOverlay->setGeometry(this->rect());
    m_progressOverlay->setVisible(true);

    QWidget *pageWidget = ui->stackedWidgetDecrypt->currentWidget();
    setWidgetInteractiveRecursive(pageWidget, false, m_progressOverlay);

    auto progressCb = [this](int percent){
        QMetaObject::invokeMethod(this, [this, percent](){
            m_progressBar->setValue(percent);
            m_progressLabel->setText(QString::number(percent) + "%");
        }, Qt::QueuedConnection);
    };

    auto future = QtConcurrent::run([this, savePath, key, progressCb]() -> bool {
        bool ok = this->decryptFile(this->m_currentDecryptFilePath, savePath, key, progressCb);
        return ok;
    });

    m_workerWatcherDecrypt->setFuture(future);
}

void MainWindow::onDecryptionFinished()
{
    bool success = m_workerWatcherDecrypt->result();

    m_progressOverlay->setVisible(false);
    QWidget *pageWidget = ui->stackedWidgetDecrypt->currentWidget();
    setWidgetInteractiveRecursive(pageWidget, true, m_progressOverlay);

    if (success) {
        QMessageBox::information(this, tr("解密成功"), tr("文件解密成功"));
        // 不跳回上一页
    } else {
        if (m_cancelRequested.loadRelaxed()) {
            QMessageBox::information(this, tr("已取消"), tr("解密已取消"));
        } else {
            QMessageBox::critical(this, tr("错误"), tr("文件解密失败（可能是密钥或文件损坏）"));
        }
    }
}

// 实现：块流式 AES-128-GCM 加密，输出格式： "SEFS"(4) + version(1) + iv(12) + ciphertext + tag(16)
bool MainWindow::encryptFile(const QString &inputPath, const QString &outputPath, const QByteArray &key, const QByteArray &iv,
                             const std::function<void(int)> &progressCallback)
{
    const QByteArray magic = QByteArray("SEFS");
    const unsigned char VERSION = 1;
    QFile in(inputPath);
    if (!in.open(QIODevice::ReadOnly)) return false;
    QFile out(outputPath);
    if (!out.open(QIODevice::WriteOnly)) {
        in.close();
        return false;
    }

    qint64 totalSize = in.size();
    qint64 processed = 0;
    const int BUF_SZ = 64 * 1024;
    QByteArray inBuf;
    inBuf.resize(BUF_SZ);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        in.close(); out.close();
        return false;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        in.close(); out.close();
        return false;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        in.close(); out.close();
        return false;
    }
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char*)key.constData(), (const unsigned char*)iv.constData())) {
        EVP_CIPHER_CTX_free(ctx);
        in.close(); out.close();
        return false;
    }

    // 写头
    out.write(magic);
    out.putChar((char)VERSION);
    out.write(iv);

    QByteArray outBuf;
    outBuf.resize(BUF_SZ + EVP_CIPHER_block_size(EVP_aes_128_gcm()));
    int outLen = 0;

    while (!in.atEnd()) {
        if (m_cancelRequested.loadRelaxed()) { // 取消处理
            EVP_CIPHER_CTX_free(ctx);
            in.close();
            out.close();
            out.remove(); // 删除不完整文件
            return false;
        }
        qint64 read = in.read(inBuf.data(), inBuf.size());
        if (read <= 0) break;
        if (1 != EVP_EncryptUpdate(ctx,
                                   (unsigned char*)outBuf.data(), &outLen,
                                   (const unsigned char*)inBuf.constData(), (int)read)) {
            EVP_CIPHER_CTX_free(ctx);
            in.close(); out.close();
            out.remove();
            return false;
        }
        out.write(outBuf.constData(), outLen);
        processed += read;
        int percent = totalSize > 0 ? int((processed * 100) / totalSize) : 0;
        if (percent > 100) percent = 100;
        progressCallback(percent);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char*)outBuf.data(), &outLen)) {
        EVP_CIPHER_CTX_free(ctx);
        in.close(); out.close();
        out.remove();
        return false;
    }
    if (outLen > 0) out.write(outBuf.constData(), outLen);

    unsigned char tag[16];
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag)) {
        EVP_CIPHER_CTX_free(ctx);
        in.close(); out.close();
        out.remove();
        return false;
    }
    out.write((const char*)tag, sizeof(tag));

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();
    progressCallback(100);
    return true;
}

// 解密函数：解析头并解密，校验 tag
bool MainWindow::decryptFile(const QString &inputPath, const QString &outputPath, const QByteArray &key,
                             const std::function<void(int)> &progressCallback)
{
    QFile in(inputPath);
    if (!in.open(QIODevice::ReadOnly)) return false;
    QByteArray magic = in.read(4);
    if (magic != "SEFS") { in.close(); return false; }
    char versionChar = 0;
    if (in.read(&versionChar, 1) != 1) { in.close(); return false; }
    int version = (unsigned char)versionChar;
    if (version != 1) { in.close(); return false; }

    QByteArray iv = in.read(12);
    if (iv.size() != 12) { in.close(); return false; }

    // 剩下文件大小 = ciphertext + tag(16)
    qint64 totalRemaining = in.size() - in.pos();
    if (totalRemaining <= 16) { in.close(); return false; }
    qint64 cipherSize = totalRemaining - 16;

    QFile out(outputPath);
    if (!out.open(QIODevice::WriteOnly)) { in.close(); return false; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { in.close(); out.close(); return false; }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx); in.close(); out.close(); return false;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        EVP_CIPHER_CTX_free(ctx); in.close(); out.close(); return false;
    }
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char*)key.constData(), (const unsigned char*)iv.constData())) {
        EVP_CIPHER_CTX_free(ctx); in.close(); out.close(); return false;
    }

    const int BUF_SZ = 64 * 1024;
    QByteArray inBuf;
    inBuf.resize(BUF_SZ);
    QByteArray outBuf;
    outBuf.resize(BUF_SZ + EVP_CIPHER_block_size(EVP_aes_128_gcm()));
    qint64 processed = 0;

    while (processed < cipherSize) {
        if (m_cancelRequested.loadRelaxed()) {
             EVP_CIPHER_CTX_free(ctx);
             in.close(); out.close();
             out.remove();
             return false;
         }
        qint64 toRead = qMin<qint64>(BUF_SZ, cipherSize - processed);
        qint64 actually = in.read(inBuf.data(), toRead);
        if (actually <= 0) break;
        int outLen = 0;
        if (1 != EVP_DecryptUpdate(ctx,
                                   (unsigned char*)outBuf.data(), &outLen,
                                   (const unsigned char*)inBuf.constData(), (int)actually)) {
            EVP_CIPHER_CTX_free(ctx);
            in.close(); out.close(); out.remove();
            return false;
        }
        out.write(outBuf.constData(), outLen);
        processed += actually;
        int percent = cipherSize > 0 ? int((processed * 100) / cipherSize) : 0;
        if (percent > 100) percent = 100;
        progressCallback(percent);
    }

    // 读取 tag（最后16字节）
    unsigned char tag[16];
    if (in.read((char*)tag, sizeof(tag)) != (int)sizeof(tag)) {
        EVP_CIPHER_CTX_free(ctx); in.close(); out.close(); out.remove();
        return false;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag)) {
        EVP_CIPHER_CTX_free(ctx); in.close(); out.close(); out.remove();
        return false;
    }

    int finalOut = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)outBuf.data(), &finalOut)) {
        // 校验失败（tag mismatch）
        EVP_CIPHER_CTX_free(ctx); in.close(); out.close(); out.remove();
        return false;
    }
    if (finalOut > 0) out.write(outBuf.constData(), finalOut);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();
    progressCallback(100);
    return true;
}

// 日志记录函数
void MainWindow::logOperation(const QString &operation, const QString &originalFilePath,
                              const QString &resultFilePath, qint64 originalSize,
                              qint64 resultSize, const QString &key)
{
    QString logEntry = QString("[%1] %2操作:\n"
                               "  原文件: %3 (%4)\n"
                               "  目标文件: %5 (%6)\n"
                               "  密钥: %7\n"
                               "----------------------------------------")
                           .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"))
                           .arg(operation)
                           .arg(QDir::toNativeSeparators(originalFilePath))
                           .arg(formatFileSize(originalSize))
                           .arg(QDir::toNativeSeparators(resultFilePath))
                           .arg(formatFileSize(resultSize))
                           .arg(key.isEmpty() ? "无" : key);

    m_logEntries.append(logEntry);
    refreshLogList(ui->lineEditSearch->text());
    saveLogsToFile();
}

QString MainWindow::getLogFilePath()
{
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dir.isEmpty()) dir = QDir::homePath() + "/.SimpleEncryption";
    QDir d(dir);
    if (!d.exists()) d.mkpath(".");
    return d.filePath("logs.txt");
}

void MainWindow::loadLogsFromFile()
{
    m_logEntries.clear();
    QFile f(getLogFilePath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QTextStream in(&f);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    in.setCodec("UTF-8");
#else
    in.setEncoding(QStringConverter::Utf8);
#endif
    QString all = in.readAll();
    f.close();
    // 日志之间用分隔线分割（兼容以前保存格式）
    const QString sep = "\n----------------------------------------";
    QStringList parts = all.split(sep, Qt::SkipEmptyParts);
    for (QString part : parts) {
        part = part.trimmed();
        if (!part.isEmpty()) {
            if (!part.endsWith("----------------------------------------"))
                part += "\n----------------------------------------";
            m_logEntries.append(part);
        }
    }
}

void MainWindow::saveLogsToFile()
{
    QFile f(getLogFilePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return;
    QTextStream out(&f);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    out.setCodec("UTF-8");
#else
    out.setEncoding(QStringConverter::Utf8);
#endif
    for (const QString &entry : qAsConst(m_logEntries)) {
        out << entry << "\n";
    }
    f.close();
}

// 刷新日志列表（支持过滤） — 调整后根据文本计算每项高度，避免被截断
void MainWindow::refreshLogList(const QString &filter)
{
    if (!ui->listWidgetLogs) return;
    ui->listWidgetLogs->clear();

    const int viewportWidth = qMax(100, ui->listWidgetLogs->viewport()->width() - 8); // 留些内边距
    QFontMetrics fm(ui->listWidgetLogs->font());

    for (int i = 0; i < m_logEntries.size(); ++i) {
        const QString &entry = m_logEntries.at(i);
        if (filter.isEmpty() || entry.contains(filter, Qt::CaseInsensitive)) {
            QListWidgetItem *it = new QListWidgetItem(entry);
            it->setData(Qt::UserRole, i); // 保存原始索引，便于删除

            // 计算多行包裹时所需高度
            QRect br = fm.boundingRect(0, 0, viewportWidth, 10000,
                                      Qt::TextWordWrap, entry);
            QSize hint = br.size();
            // 增加一些垂直与水平间距
            hint.rwidth() += 8;
            hint.rheight() += 8;
            it->setSizeHint(hint);

            ui->listWidgetLogs->addItem(it);
        }
    }
    // 若当前为空并且有 filter，可能需要显示提示
    if (ui->listWidgetLogs->count() == 0 && !filter.isEmpty()) {
        QListWidgetItem *it = new QListWidgetItem(tr("无匹配日志"));
        it->setFlags(Qt::NoItemFlags);
        ui->listWidgetLogs->addItem(it);
    }
}

void MainWindow::onSearchTextChanged(const QString &text)
{
    refreshLogList(text);
}

void MainWindow::onLogListCustomContextMenuRequested(const QPoint &pos)
{
    if (!ui->listWidgetLogs) return;
    QListWidgetItem *item = ui->listWidgetLogs->itemAt(pos);
    QMenu menu(this);
    QAction *copyAct = menu.addAction(tr("复制内容"));
    QAction *copyKeyAct = menu.addAction(tr("复制密钥")); // 新增：复制密钥
    QAction *deleteAct = menu.addAction(tr("删除条目"));
    QAction *saveAct = menu.addAction(tr("另存为..."));

    QAction *act = menu.exec(ui->listWidgetLogs->viewport()->mapToGlobal(pos));
    if (!act || !item) return;

    if (act == copyAct) {
        QApplication::clipboard()->setText(item->text());
    } else if (act == copyKeyAct) {
        // 从日志条目中提取 "密钥: <value>" 并复制到剪贴板
        QString entry = item->text();
        QRegularExpression re("密钥:\\s*([^\\s\\n]+)");
        QRegularExpressionMatch match = re.match(entry);
        if (!match.hasMatch()) {
            QMessageBox::warning(this, tr("错误"), tr("无法从该日志条目中提取密钥"));
        } else {
            QString key = match.captured(1);
            if (key == "无") {
                QMessageBox::information(this, tr("提示"), tr("该日志条目不包含密钥"));
            } else {
                QApplication::clipboard()->setText(key);
                QMessageBox::information(this, tr("复制成功"), tr("密钥已复制到剪贴板"));
            }
        }
    } else if (act == deleteAct) {
        bool ok = false;
        int originalIndex = item->data(Qt::UserRole).toInt(&ok);
        if (ok && originalIndex >= 0 && originalIndex < m_logEntries.size()) {
            m_logEntries.removeAt(originalIndex);
            saveLogsToFile();
            refreshLogList(ui->lineEditSearch ? ui->lineEditSearch->text() : QString());
        }
    } else if (act == saveAct) {
        QString defaultName = QDir::homePath() + "/log_entry.txt";
        QString fileName = QFileDialog::getSaveFileName(this, tr("另存为日志条目"), defaultName, tr("文本文件 (*.txt);;所有文件 (*)"));
        if (fileName.isEmpty()) return;
        QFile f(fileName);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(this, tr("错误"), tr("无法保存文件: %1").arg(f.errorString()));
            return;
        }
        QTextStream out(&f);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
        out.setCodec("UTF-8");
#else
        out.setEncoding(QStringConverter::Utf8);
#endif
        out << item->text();
        f.close();
        QMessageBox::information(this, tr("成功"), tr("日志条目已保存到: %1").arg(fileName));
    }
}

// 复制选中日志条目到剪贴板（支持多选）
void MainWindow::onCopyLogEntry()
{
    if (!ui || !ui->listWidgetLogs) return;
    QList<QListWidgetItem*> items = ui->listWidgetLogs->selectedItems();
    if (items.isEmpty()) return;

    QStringList texts;
    for (QListWidgetItem *it : items) {
        texts << it->text();
    }
    QApplication::clipboard()->setText(texts.join("\n\n"));
}

// 删除选中日志条目（从 m_logEntries 中移除并保存）
void MainWindow::onDeleteLogEntry()
{
    if (!ui || !ui->listWidgetLogs) return;
    QList<QListWidgetItem*> items = ui->listWidgetLogs->selectedItems();
    if (items.isEmpty()) return;

    // 收集要删除的原始索引，去重并降序排序以安全移除
    QVector<int> indices;
    for (QListWidgetItem *it : items) {
        bool ok = false;
        int idx = it->data(Qt::UserRole).toInt(&ok);
        if (ok) indices.append(idx);
    }
    if (indices.isEmpty()) return;
    std::sort(indices.begin(), indices.end(), std::greater<int>());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());

    for (int idx : indices) {
        if (idx >= 0 && idx < m_logEntries.size()) {
            m_logEntries.removeAt(idx);
        }
    }
    saveLogsToFile();
    refreshLogList(ui->lineEditSearch ? ui->lineEditSearch->text() : QString());
}

// 将选中条目另存为文件（若多选则合并保存）
void MainWindow::onSaveLogEntry()
{
    if (!ui || !ui->listWidgetLogs) return;
    QList<QListWidgetItem*> items = ui->listWidgetLogs->selectedItems();
    if (items.isEmpty()) return;

    QString defaultName = QDir::homePath() + "/log_entry.txt";
    QString fileName = QFileDialog::getSaveFileName(this, tr("另存为日志条目"), defaultName, tr("文本文件 (*.txt);;所有文件 (*)"));
    if (fileName.isEmpty()) return;

    QFile f(fileName);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("错误"), tr("无法保存文件: %1").arg(f.errorString()));
        return;
    }
    QTextStream out(&f);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    out.setCodec("UTF-8");
#else
    out.setEncoding(QStringConverter::Utf8);
#endif

    for (int i = 0; i < items.size(); ++i) {
        out << items.at(i)->text();
        if (i != items.size() - 1) out << "\n\n";
    }
    f.close();
    QMessageBox::information(this, tr("成功"), tr("日志条目已保存到: %1").arg(fileName));
}

QString MainWindow::formatFileSize(qint64 bytes)
{
    if (bytes < 0) bytes = 0;
    if (bytes < 1024) {
        return QString("%1 B").arg(bytes);
    }
    double k = bytes / 1024.0;
    if (k < 1024.0) {
        return QString("%1 KB").arg(QString::number(k, 'f', 2));
    }
    double m = k / 1024.0;
    if (m < 1024.0) {
        return QString("%1 MB").arg(QString::number(m, 'f', 2));
    }
    double g = m / 1024.0;
    return QString("%1 GB").arg(QString::number(g, 'f', 2));
}

// helper：递归设置页面内控件的可交互性（使用 findChildren 简化）
static void setWidgetInteractiveRecursive(QWidget *root, bool enable, QWidget *exclude)
{
    if (!root) return;
    // 获取所有子孙控件并设置 enabled（排除 overlay）
    const QList<QWidget*> children = root->findChildren<QWidget*>(QString(), Qt::FindChildrenRecursively);
    for (QWidget *w : children) {
        if (!w || w == exclude) continue;
        w->setEnabled(enable);
    }
    // 可根据需要同时处理 root 自身
    if (root != exclude) root->setEnabled(enable);
}

// 新增：重写 resizeEvent，在主线程中同步 overlay 大小
void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    if (m_progressOverlay) {
        m_progressOverlay->setGeometry(this->rect());
    }
}

// helper 前向声明已在顶部。
// 实现：生成随机字节（基于 OpenSSL RAND_bytes）
QByteArray MainWindow::generateRandomData(int size)
{
    if (size <= 0) return QByteArray();
    QByteArray buf;
    buf.resize(size);
    // RAND_bytes 返回 1 表示成功
    if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), size) == 1) {
        return buf;
    }
    return QByteArray();
}

// 校验解密密钥是否为 32 位十六进制字符串（对应 16 字节密钥）
bool MainWindow::validateDecryptionKey(const QString &keyHex)
{
    if (keyHex.length() != 32) return false;
    static const QRegularExpression re("^[0-9A-Fa-f]{32}$");
    return re.match(keyHex).hasMatch();
}

// 选择要解密的文件（弹出资源管理器）
void MainWindow::onSelectDecryptFileClicked()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("选择要解密的文件"),
        QString(),
        tr("SEFS Files (*.sefs);;All Files (*)")
    );

    if (filePath.isEmpty()) return;

    QFileInfo fi(filePath);
    if (!fi.exists()) {
        QMessageBox::warning(this, tr("文件错误"), tr("选择的文件不存在"));
        return;
    }

    // 可选：校验后缀
    if (fi.suffix().compare("sefs", Qt::CaseInsensitive) != 0) {
        QMessageBox::warning(this, tr("文件格式错误"), tr("请选择 .sefs 加密文件"));
        return;
    }

    m_currentDecryptFilePath = filePath;
    updateDecryptFileInfoDisplay();
}

// 重新选择解密文件（在解密页面）
void MainWindow::onDecryptBackButtonClicked()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("选择要解密的文件"),
        QString(),
        tr("SEFS Files (*.sefs);;All Files (*)")
    );

    if (filePath.isEmpty()) {
        ui->stackedWidgetDecrypt->setCurrentIndex(0);
        return;
    }

    QFileInfo fi(filePath);
    if (!fi.exists()) {
        QMessageBox::warning(this, tr("文件错误"), tr("选择的文件不存在"));
        ui->stackedWidgetDecrypt->setCurrentIndex(0);
        return;
    }

    if (fi.suffix().compare("sefs", Qt::CaseInsensitive) != 0) {
        QMessageBox::warning(this, tr("文件格式错误"), tr("请选择 .sefs 加密文件"));
        return;
    }

    m_currentDecryptFilePath = filePath;
    updateDecryptFileInfoDisplay();
}

// 更新解密页面的文件信息显示（与加密页对称）
void MainWindow::updateDecryptFileInfoDisplay()
{
    if (m_currentDecryptFilePath.isEmpty()) {
        ui->stackedWidgetDecrypt->setCurrentIndex(0);
        return;
    }

    QFileInfo fileInfo(m_currentDecryptFilePath);
    QString fileName = fileInfo.fileName();
    QFontMetrics fm(ui->labelDecryptFileNameValue->font());

    int fileNameWidth = qMax(50, ui->labelDecryptFileNameValue->width() - 10);
    QString elidedFileName = fm.elidedText(fileName, Qt::ElideMiddle, fileNameWidth);
    if (elidedFileName.isEmpty()) elidedFileName = fileName;
    ui->labelDecryptFileNameValue->setText(elidedFileName);
    ui->labelDecryptFileNameValue->setToolTip(fileName);
    ui->labelDecryptFileNameValue->setVisible(true);

    QString fullPath = QDir::toNativeSeparators(fileInfo.absoluteFilePath());
    int pathWidth = qMax(50, ui->labelDecryptFilePathValue->width() - 10);
    QString elidedPath = fm.elidedText(fullPath, Qt::ElideMiddle, pathWidth);
    if (elidedPath.isEmpty()) elidedPath = fullPath;
    ui->labelDecryptFilePathValue->setText(elidedPath);
    ui->labelDecryptFilePathValue->setToolTip(fullPath);
    ui->labelDecryptFilePathValue->setVisible(true);

    qint64 fileSize = fileInfo.size();
    ui->labelDecryptFileSizeValue->setText(formatFileSize(fileSize));

    ui->stackedWidgetDecrypt->setCurrentIndex(1);
    // 清空密钥输入以提示用户重新输入
    if (ui->lineEditDecryptKey) ui->lineEditDecryptKey->clear();
}
