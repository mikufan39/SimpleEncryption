#include "mainwindow.h"

#include <QApplication>
#include <QLocale>
#include <QTranslator>
#include "singleinstance.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

static QString makeUniqueKey()
{
    QString user = qEnvironmentVariable("USERNAME");
    if (user.isEmpty()) user = qEnvironmentVariable("USER");
    return QStringLiteral("SimpleEncryption_InstanceKey_%1").arg(user);
}

int main(int argc, char *argv[])
{
    // 修正OpenSSL初始化
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    QApplication a(argc, argv);

    SingleInstance instance(makeUniqueKey());
    if (!instance.tryRunAsPrimary()) {
        instance.sendMessage("raise");
        return 0;
    }

    MainWindow w;
    w.show();
    QObject::connect(&instance, &SingleInstance::messageReceived,
                     &w, [&w](const QByteArray& msg){
                         Q_UNUSED(msg);
                         w.bringToForeground();
                     });

    return a.exec();
}
